#!/usr/bin/python

import ldap
import ldap.sasl
import hashlib
import os

from ansible.module_utils.basic import *

def get_hashed_passwd(passwd):
    salt = os.urandom(4)
    sha = hashlib.sha1(passwd)
    sha.update(salt)

    digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()
    tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)
    return tagged_digest_salt

def get_password(passwd):
    conn = ldap.initialize('ldapi:///')
    conn.sasl_interactive_bind_s('', ldap.sasl.external())
    distnm = 'olcDatabase={2}hdb'
    attrname = 'olcRootPW'
    base = 'cn=config'
    recs = conn.search_s(base, ldap.SCOPE_SUBTREE, distnm, [attrname])
    conn.unbind()

    if recs[0][1]:
        tagged_digest_salt = recs[0][1][attrname][0]
        if tagged_digest_salt.startswith('{SSHA}'):
            digest_salt_b64 = tagged_digest_salt[6:]
            digest_salt = digest_salt_b64.decode('base64')
            salt = digest_salt[20:]
            digest = digest_salt[:20]
            sha = hashlib.sha1(passwd)
            sha.update(salt)
            if digest == sha.digest():
                return tagged_digest_salt

    return get_hashed_passwd(passwd)

    
def main():
    module = AnsibleModule(argument_spec={
        'password': dict(required=True, no_log=True),
        },
        supports_check_mode=True,
    )

    passhash = get_password(module.params['password'])
    module.exit_json(changed=False, meta=passhash)

if __name__ == '__main__':
    main()
    
