# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

import asn1crypto.csr
from asn1crypto.util import OrderedDict
from oscrypto import asymmetric
from csrbuilder import CSRBuilder


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CSRBuilderTests(unittest.TestCase):

    def test_build_basic(self):
        public_key, private_key = asymmetric.generate_pair('ec', curve='secp256r1')

        builder = CSRBuilder(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            public_key
        )
        builder.subject_alt_domains = ['codexns.io', 'codexns.com']
        request = builder.build(private_key)
        der_bytes = request.dump()

        new_request = asn1crypto.csr.CertificationRequest.load(der_bytes)
        cri = new_request['certification_request_info']

        self.assertEqual('sha256_ecdsa', new_request['signature_algorithm']['algorithm'].native)
        self.assertEqual(1, len(cri['attributes']))
        self.assertEqual('extension_request', cri['attributes'][0]['type'].native)

        extensions = cri['attributes'][0]['values'][0]
        self.assertEqual(4, len(extensions))

        self.assertEqual('basic_constraints', extensions[0]['extn_id'].native)
        self.assertEqual(
            OrderedDict([('ca', False), ('path_len_constraint', None)]),
            extensions[0]['extn_value'].native
        )

        self.assertEqual('extended_key_usage', extensions[1]['extn_id'].native)
        self.assertEqual(
            ['server_auth', 'client_auth'],
            extensions[1]['extn_value'].native
        )

        self.assertEqual('key_usage', extensions[2]['extn_id'].native)
        self.assertEqual(
            set(['digital_signature', 'key_encipherment']),
            extensions[2]['extn_value'].native
        )

        self.assertEqual('subject_alt_name', extensions[3]['extn_id'].native)
        self.assertEqual(
            ['codexns.io', 'codexns.com'],
            extensions[3]['extn_value'].native
        )
