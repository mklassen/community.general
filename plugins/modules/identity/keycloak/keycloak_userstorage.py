#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018, Eike Frost <ei@kefro.st>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: keycloak_userstorage

short_description: Allows administration of Keycloak user storage provider components via Keycloak API

version_added: "2.6"

description:
    - This module allows the administration of Keycloak user storage provider components via the
      Keycloak REST API. It requires access to the REST API via OpenID Connect; the user connecting
      and the client being used must have the requisite access rights. In a default Keycloak
      installation, admin-cli and an admin user would work, as would a separate client definition
      with the scope tailored to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(http://www.keycloak.org/docs-api/3.4/rest-api/).
      Aliases are provided (if an option has an alias, it is the camelCase'd version used in the
      API).

options:
    state:
        description:
            - State of the user storage provider once this module has run
            - On C(present), the user storage provider will be created (or updated if it exists already).
            - On C(absent), the user storage provider will be removed if it exists
        choices: ['present', 'absent']
        default: 'present'


TODO

notes:
    -

extends_documentation_fragment:
    - keycloak

author:
    - Eike Frost (@eikef)
'''

EXAMPLES = '''
'''

RETURN = '''
msg:
  description: Message as to what action was taken
  returned: always
  type: string
  sample:

proposed:
    description:
    returned: always
    type: dict
    sample:

existing:
    description:
    returned: always
    type: dict
    sample:

end_state:
    description:
    returned: always
    type: dict
    sample:
'''

from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak import KeycloakAPI, camel, \
    keycloak_argument_spec, get_token
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Module execution

    :return:
    """
    argument_spec = keycloak_argument_spec()

    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(type='str', required=True),
        id=dict(type='str'),
        name=dict(type='str'),
        provider_id=dict(type='str', choices=['ldap', 'kerberos'], default='ldap',
                         aliases=['providerId']),
        config=dict(type='dict')
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of = ([['name', 'id']]))

    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={})

    realm = module.params.get('realm')
    state = module.params.get('state')

    # Obtain access token, initialize API
    try:
        connection_header = get_token(
            base_url=module.params.get('auth_keycloak_url'),
            validate_certs=module.params.get('validate_certs'),
            auth_realm=module.params.get('auth_realm'),
            client_id=module.params.get('auth_client_id'),
            auth_username=module.params.get('auth_username'),
            auth_password=module.params.get('auth_password'),
            client_secret=module.params.get('auth_client_secret'),
            )
    except KeycloakError as e:
        module.fail_json(msg=str(e))
    kc = KeycloakAPI(module, connection_header)

    # Attempt to get an id for a name
    if module.params.get('id') is None:
        us_list = kc.get_components(realm=realm, name=module.params.get('name'))
        if len(us_list) == 1:
            module.params['id'] = us_list[0]['id']

    # convert module parameters to user storage provider representation parameters
    # (if they belong in there)
    us_params = [x for x in module.params
                 if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm'] and
                 module.params.get(x) is not None]

    before_us = kc.get_component_by_id(module.params.get('id'), realm=realm)
    before_us = {} if before_us is None else before_us

    # For an unknown reason, all parameters in the config dict must be lists, regardless of whether
    # a parameter actually takes a list. Make sure that all given parameters are lists.

    if module.params.get('config') is not None:
        config = module.params.get('config')
        for item in config.keys():
            if not isinstance(config[item], list):
                config[item] = [config[item]]

            # camelCase keys that are not yet camelCased
            if camel(item) != item:
                config[camel(item)] = config[item]
                del config[item]

        # Do validity-checking of config dict; this cannot reasonably be done with the
        # argument_spec since the contents differ based on what provider type is used

        if module.params.get('provider_id') == 'ldap':
            intarguments = ['priority', 'fullSyncPeriod', 'changedSyncPeriod', 'evictionDay',
                            'evictionHour', 'evictionMinute', 'maxLifespan', 'batchSizeForSync',
                            'connectionTimeout', 'readTimeout', ]
            boolarguments = ['importEnabled', 'syncRegistrations', 'validatePasswordPolicy',
                             'connectionPooling', 'pagination', 'allowKerberosAuthentication',
                             'debug', 'useKerberosForPasswordAuthentication', 'enabled', 'startTls',
                             'trustEmail']
            argumentlist = ['cachePolicy', 'editMode', 'vendor', 'usernameLDAPAttribute',
                            'rdnLDAPAttribute', 'uuidLDAPAttribute', 'userObjectClasses',
                            'connectionUrl', 'usersDn', 'authType', 'bindDn', 'bindCredential',
                            'customUserSearchFilter', 'searchScope',  'useTruststoreSpi',
                            'serverPrincipal', 'keyTab', 'kerberosRealm'
                            ] + intarguments + boolarguments

            for item in config.keys():
                if item not in argumentlist:
                    module.fail_json(msg="'%s' is not a valid configuration parameter for LDAP user storage providers." % item)
                if len(config[item]) == 1:
                    if item in intarguments:
                        try:
                            int(config[item][0])
                        except ValueError:
                            module.fail_json (msg='"%s" must be an integer' % item )
                    if item in boolarguments:
                        if type(config[item][0]) is not bool:
                            if config[item][0] not in ['true', 'false', 'True', 'False']:
                                module.fail_json(msg='"%s" must be a boolean' % item)
                            config[item][0] = True if config[item][0].lower() == 'true' else False
                        config[item][0] = 'true' if config[item][0] else 'false'
                    if item == 'editMode':
                        if config[item][0] not in ['READ_ONLY', 'WRITABLE', 'UNSYNCED']:
                            module.fail_json(msg='"%s" must be one of READ_ONLY, WRITABLE, UNSYNCED' % item)
                    if item == 'authType':
                        if config[item][0] not in ['simple', 'none']:
                            module.fail_json(msg='"%s" must be one of simple, none' % item)
                    if item == 'searchScope':
                        if int(config[item][0]) not in [1, 2]:
                            module.fail_json(msg='"%s" must be one of 1, 2' % item)
                    if item == 'useTrustStoreSpi':
                        if config[item][0] not in ['ldapsOnly', 'always', 'never']:
                            module.fail_json(msg='"%s" must be one of ldapsOnly, always, never' % item)
                    if item == 'cachePolicy':
                        if config[item][0] not in ['DEFAULT', 'EVICT_DAILY', 'EVICT_WEEKLY', 'MAX_LIFESPAN', 'NO_CACHE']:
                            module.fail_json(msg='"%s" must be one of DEFAULT, EVICT_DAILY, EVICT_WEEKLY, MAX_LIFESPAN, NO_CACHE' % item)
                elif len(config[item]) > 1:
                    module.fail_json(msg='"%s" may only contain one item, not a list' % item)
        elif module.params.get('provider_id') == 'kerberos':
            intarguments = ['priority', 'evictionDay', 'evictionHour', 'evictionMinute',
                            'maxLifespan']
            boolarguments = ['debug', 'allowPasswordAuthentication', 'updateProfileFirstLogin']
            argumentlist = ['cachePolicy', 'kerberosRealm', 'serverPrincipal', 'keyTab', 'editMode'
                            ] + intarguments + boolarguments
            for item in config.keys():
                if item not in argumentlist:
                    module.fail_json(msg="'%s' is not a valid configuration parameter for LDAP user storage providers." % item)
                if len(config[item]) == 1:
                    if item in intarguments:
                        try:
                            int(config[item][0])
                        except ValueError:
                            module.fail_json (msg='"%s" must be an integer' % item )
                    if item in boolarguments:
                        if config[item][0] not in ['true', 'false', 'True', 'False']:
                            module.fail_json(msg='"%s" must be a boolean' % item)
                    if item == 'editMode':
                        if config[item][0] not in ['READ_ONLY', 'WRITABLE', 'UNSYNCED']:
                            module.fail_json(msg='"%s" must be one of READ_ONLY, WRITABLE, UNSYNCED' % item)
                    if item == 'cachePolicy':
                        if config[item][0] not in ['DEFAULT', 'EVICT_DAILY', 'EVICT_WEEKLY', 'MAX_LIFESPAN', 'NO_CACHE']:
                            module.fail_json(msg='"%s" must be one of DEFAULT, EVICT_DAILY, EVICT_WEEKLY, MAX_LIFESPAN, NO_CACHE' % item)
                elif len(config[item]) > 1:
                    module.fail_json(msg='"%s" may only contain one item, not a list' % item)

    # Build a proposed changeset from parameters given to this module
    changeset = dict()

    for us_param in us_params:
        changeset[camel(us_param)] = module.params.get(us_param)

    changeset['providerType'] = 'org.keycloak.storage.UserStorageProvider'
    changeset['parentId'] = module.params.get('realm')

    # Whether creating or updating a client, take the before-state and merge the changeset into it
    updated_us = before_us.copy()
    updated_us.update(changeset)

    result['proposed'] = changeset
    result['existing'] = before_us

    # If the client does not exist yet, before_client is still empty
    if before_us == dict():
        if state == 'absent':
            # do nothing and exit
            if module._diff:
                result['diff'] = dict(before='', after='')
            result['msg'] = 'User Storage component does not exist, doing nothing.'
            module.exit_json(**result)

        # create new user storage component
        result['changed'] = True

        if module.check_mode:
            if module._diff:
                result['diff'] = dict(before='', after=updated_us)

            module.exit_json(**result)

        create_result = kc.create_component(updated_us, realm=realm)
        created_id = create_result.getheader('Location').split('/')[-1]

        after_us = kc.get_component_by_id(created_id, realm=realm)

        if module._diff:
            result['diff'] = dict(before='', after=after_us)

        result['end_state'] = after_us

        result['msg'] = 'User storage provider %s in realm %s has been created.' % (after_us['name'], realm)
        module.exit_json(**result)
    else:
        if state == 'present':
            # update existing realm
            result['changed'] = True
            if module.check_mode:
                # We can only compare the current user storage provider with the proposed
                # updates we have
                if module._diff:
                    result['diff'] = dict(before=before_us,
                                          after=updated_us)

                module.exit_json(**result)

            kc.update_component(module.params.get('id'), updated_us, realm=realm)

            after_us = kc.get_component_by_id(module.params.get('id'), realm=realm)

            if before_us == after_us:
                result['changed'] = False
            if module._diff:
                result['diff'] = dict(before=before_us,
                                      after=after_us)
            result['end_state'] = after_us

            result['msg'] = 'User storage provider %s has been updated.' % after_us['name']
            module.exit_json(**result)
        else:
            # Delete existing user storage provider
            result['changed'] = True
            if module._diff:
                result['diff']['before'] = before_us
                result['diff']['after'] = ''

            if module.check_mode:
                module.exit_json(**result)

            kc.delete_component(module.params.get('id'), realm=realm)
            result['proposed'] = dict()
            result['end_state'] = dict()
            result['msg'] = 'User storage provider %s has been deleted.' % before_us['name']
            module.exit_json(**result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
