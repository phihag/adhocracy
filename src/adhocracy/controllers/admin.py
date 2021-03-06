import logging

import formencode
import formencode.htmlfill
from pylons import request, tmpl_context as c
from pylons.i18n import lazy_ugettext as L_, _
from pylons.controllers.util import redirect

from adhocracy import config
from adhocracy import model, forms
from adhocracy.lib.auth import guard
from adhocracy.lib.auth.csrf import RequireInternalRequest
from adhocracy.lib.auth.welcome import can_welcome
from adhocracy.lib.base import BaseController
from adhocracy.lib.helpers import base_url, flash
from adhocracy.lib.templating import render, ret_abort
from adhocracy.lib.search import index
from adhocracy.lib.user_import import user_import, get_user_import_state
import adhocracy.lib.importexport

log = logging.getLogger(__name__)


class UserImportForm(formencode.Schema):
    allow_extra_fields = True
    users_csv = forms.UsersCSV()
    email_subject = formencode.validators.String(
        not_empty=True,
        messages={'empty': L_('Please insert a subject for the '
                              'mail we will send to the users.')})
    email_template = forms.ContainsEMailPlaceholders(
        not_empty=True,
        messages={'empty': L_('Please insert a template for the '
                              'mail we will send to the users.')})


class ExportForm(formencode.Schema):
    include_user = formencode.validators.StringBoolean(if_missing=False)
    include_badge = formencode.validators.StringBoolean(if_missing=False)
    include_instance = formencode.validators.StringBoolean(if_missing=False)
    include_instance_proposal = formencode.validators.StringBoolean(
        if_missing=False)
    include_instance_proposal_comment = formencode.validators.StringBoolean(
        if_missing=False)
    include_proposal_creator_badges = formencode.validators.StringBoolean(
        if_missing=False)
    include_ratings = formencode.validators.StringBoolean(if_missing=False)
    include_requestlog = formencode.validators.StringBoolean(if_missing=False)
    include_staticpage = formencode.validators.StringBoolean(if_missing=False)
    user_personal = formencode.validators.StringBoolean(if_missing=False)
    user_password = formencode.validators.StringBoolean(if_missing=False)
    format = formencode.validators.OneOf(
        ['json', 'json_download', 'json_gzip',
         'zip',
         'tar', 'tar_gz', 'tar_bz2'])
    _tok = formencode.validators.String()


class ImportForm(formencode.Schema):
    include_user = formencode.validators.StringBoolean(if_missing=False)
    welcome = formencode.validators.StringBoolean(if_missing=False)
    include_badge = formencode.validators.StringBoolean(if_missing=False)
    include_instance = formencode.validators.StringBoolean(if_missing=False)
    include_instance_proposal = formencode.validators.StringBoolean(
        if_missing=False)
    include_staticpage = formencode.validators.StringBoolean(if_missing=False)
    filetype = formencode.validators.OneOf(['detect', 'json', 'zip'])
    importfile = formencode.validators.FieldStorageUploadConverter(
        not_empty=True)
    replacement = formencode.validators.OneOf(['update', 'skip'])
    _tok = formencode.validators.String()


class AdminController(BaseController):

    identifier = 'admin'

    @guard.perm("global.admin")
    def index(self):
        return render("/admin/index.html", {})

    @guard.perm("global.admin")
    def update_index(self):
        for entity_type in model.refs.TYPES:
            if hasattr(entity_type, "all"):
                for entity in entity_type.all():
                    index.update(entity)
        flash(_('Solr index updated.'), 'success')
        redirect(base_url('/admin'))

    @guard.perm("global.admin")
    def fix_autojoin(self):
        config_autojoin = config.get('adhocracy.instances.autojoin')
        if not config_autojoin:
            return ret_abort('autojoin is not enabled')

        users = model.User.all()
        added = 0
        for user in users:
            added += user.fix_autojoin(commit=False)
        if added > 0:
            model.meta.Session.commit()
            flash(_('Autojoin fixed - added %s memberships.') % added,
                  'success')
        else:
            flash(_('No need to fix autojoin.'), 'success')

        return redirect(base_url('/admin'))

    @RequireInternalRequest()
    @guard.perm("global.admin")
    def permissions(self):
        if request.method == "POST":
            groups = model.Group.all(ordered=True)
            for permission in model.Permission.all():
                for group in groups:
                    t = request.params.get("%s-%s" % (
                        group.code, permission.permission_name))
                    if t and permission not in group.permissions:
                        group.permissions.append(permission)
                    elif not t and permission in group.permissions:
                        group.permissions.remove(permission)
            for group in groups:
                model.meta.Session.add(group)
            model.meta.Session.commit()
        return render("/admin/permissions.html", {})

    @guard.perm("global.admin")
    def user_import_form(self, errors=None, format='html'):
        return formencode.htmlfill.render(
            render("/admin/userimport_form.html", {},
                   overlay=format == 'overlay'),
            defaults=dict(request.params),
            errors=errors,
            force_defaults=False)

    @RequireInternalRequest(methods=['POST'])
    @guard.perm("global.admin")
    def user_import(self, format='html'):

        if request.method == "POST":
            try:
                self.form_result = UserImportForm().to_python(
                    request.params, state=get_user_import_state())
                data = user_import(self.form_result['users_csv'],
                                   self.form_result['email_subject'],
                                   self.form_result['email_template'],
                                   c.user,
                                   c.instance)
                return render("/admin/userimport_success.html", data,
                              overlay=format == u'overlay')
            except formencode.Invalid as i:
                return self.user_import_form(errors=i.unpack_errors())
        else:
            return self.user_import_form(format=format)

    @guard.perm("global.admin")
    def import_dialog(self, errors=None, defaults=None, format=u'html'):
        data = {
            'welcome_enabled': can_welcome()
        }
        if defaults is None:
            defaults = dict(request.POST)
        tpl = render('admin/import_dialog.html', data,
                     overlay=format == u'overlay')
        return formencode.htmlfill.render(
            tpl,
            defaults=defaults,
            errors=errors,
            force_defaults=False)

    @RequireInternalRequest(methods=['POST'])
    @guard.perm("global.admin")
    def import_do(self):
        try:
            options = ImportForm().to_python(dict(request.params))
        except formencode.Invalid as i:
            return self.import_dialog(errors=i.unpack_errors())

        if not can_welcome() and options['welcome']:
            return ret_abort(_("Requested generation of welcome codes, but "
                               "welcome functionality"
                               "(adhocracy.enable_welcome) is not enabled."),
                             code=403)
        obj = request.POST['importfile']
        options['user_personal'] = True
        adhocracy.lib.importexport.import_(options, obj.file)
        return render('admin/import_success.html', {})

    @guard.perm("global.admin")
    def export_dialog(self, format=u'html'):
        return render('admin/export_dialog.html', {},
                      overlay=format == u'overlay')

    @RequireInternalRequest(methods=['POST'])
    @guard.perm("global.admin")
    def export_do(self):
        options = ExportForm().to_python(dict(request.params))
        return adhocracy.lib.importexport.export(options)
        # Above writes out a file; don't render anything
