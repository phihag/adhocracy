from pylons import tmpl_context as c

from adhocracy.lib.auth import poll
from adhocracy.lib.auth.authorization import has
from adhocracy.lib.auth.authorization import NOT_JOINED


# helper functions

def is_own(p):
    return c.user and p.creator == c.user


# authorisation checks

def index(check):
    check.perm('proposal.show')


def show(check, p):
    check.perm('proposal.show')
    check.other('proposal_deleted', p.is_deleted())


def create(check, instance=None):
    check.readonly()
    check.valid_email()
    if instance is None:
        instance = c.instance
    check.other(NOT_JOINED, not c.user or not c.user.is_member(instance))
    check.other('instance_frozen', instance.frozen)
    check.perm('proposal.create')


def edit(check, p):
    check.readonly()
    check.valid_email()
    if has('instance.admin') or has('global.admin'):
        # Admins can always edit proposals.
        return

    show(check, p)
    check.other('proposal_not_mutable', not p.is_mutable())
    if has('proposal.edit'):
        # having proposal.edit is enough
        return

    check.other(NOT_JOINED, not c.user or not c.user.is_member(c.instance))
    check.other('proposal_head_not_wiki_or_own',
                not is_own(p) and not p.description.head.wiki)


def edit_badges(check, p):
    check.readonly()
    check.perm('instance.manage')


def delete(check, p):
    check.readonly()
    check.valid_email()
    if has('instance.admin'):
        return
    check.perm('proposal.delete')
    show(check, p)
    check.other('proposal_not_mutable', not p.is_mutable())


def rate(check, p):
    check.readonly()
    check.valid_email()
    check.other('proposal_frozen', p.frozen)
    check.other('instance_frozen', c.instance.frozen)
    show(check, p)
    if p.rate_poll is None:
        check.other('proposal_no_rate_poll', True)
    else:
        poll.vote(check, p.rate_poll)


def adopt(check, p):
    check.valid_email()
    if c.instance.allow_adopt and has('instance.admin'):
        return
    show(check, p)
    poll.create(check)
    check.other('proposal_cannot_adopt', not p.can_adopt())


def message(check, p):
    check.readonly()

    if has('global.message'):
        return
    check.perm('proposal.message')
