import requests

from adhocracy import config
from adhocracy import i18n


class RESTAPI(object):
    """Helper to work with the adhocarcy_service rest api
       (adhocracy_kotti.mediacenter, adhocracy_kotti.staticpages, plone).
    """

    session = requests.Session()

    def __init__(self):
        self.staticpages_api_token = config.get(
            'adhocracy_service.staticpages.rest_api_token',
            config.get('adhocracy_service.rest_api_token', ''))
        self.staticpages_api_address = config.get(
            'adhocracy_service.staticpages.rest_api_address',
            config.get('adhocracy_service.rest_api_address', ''))
        self.staticpages_verify = config.get_bool(
            'adhocracy_service.staticpages.verify_ssl',
            config.get_bool('adhocracy_service.verify_ssl', True))
        self.staticpages_headers = {"X-API-Token": self.staticpages_api_token}

    def staticpages_get(self, base=None, languages=None):
        if languages is None:
            languages = i18n.all_languages(include_preferences=True)
        params = {
            'lang': languages
        }
        if base is not None:
            params['base'] = base
        request = requests.Request("GET",
                                   url='%s%s' % (
                                       self.staticpages_api_address,
                                       "staticpages",
                                   ),
                                   params=params,
                                   headers=self.staticpages_headers)
        return self.session.send(request.prepare(),
                                 verify=self.staticpages_verify)

    def staticpage_get(self, path, languages=None):
        if languages is None:
            languages = i18n.all_languages(include_preferences=True)
        request = requests.Request("GET",
                                   url='%s%s' % (
                                       self.staticpages_api_address,
                                       'staticpages/single',
                                   ),
                                   params={
                                       'path': path,
                                       'lang': languages,
                                   },
                                   headers=self.staticpages_headers)

        return self.session.send(request.prepare(),
                                 verify=self.staticpages_verify)
