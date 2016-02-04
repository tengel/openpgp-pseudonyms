#!/usr/bin/python
__copyright__ = """
Copyright (C) Timo Engel (timo-e@freenet.de), Berlin 2012.
This program was written as part of a master thesis advised by 
Prof. Dr. Ruediger Weis at the Beuth University of Applied 
Sciences Berlin.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys
sys.path.append('..')

import unittest
import crypto

# ------------------------------------------------------------------------------

class TestCrypto(unittest.TestCase):

    def testRsa(self):
        e = 17
        n = 3233
        d = 2753
        m = 3000
        s = crypto.rsaSign(m, d, n)
        self.assertTrue(crypto.rsaVerify(s, m, e, n))

        r = 11
        bm = crypto.rsaBlind(m, r, e, n)
        bs = crypto.rsaSign(bm, d, n)
        s = crypto.rsaUnblind(r, n, bs)
        self.assertTrue(crypto.rsaVerify(s, m, e, n))


    def testForge(self):
        e = 17
        n = 3233
        d = 2753

        m1 = 11
        m2 = 19

        bm1 = crypto.rsaBlind(m1, 11, e, n)
        bs1 = pow(bm1, d, n)
        s1 = crypto.rsaUnblind(11, n, bs1)
        self.assertTrue(crypto.rsaVerify(s1, m1, e, n))

        bm2 = crypto.rsaBlind(m2, 13, e, n)
        bs2 = pow(bm2, d, n)
        s2 = crypto.rsaUnblind(13, n, bs2)
        self.assertTrue(crypto.rsaVerify(s2, m2, e, n))
        
        self.assertTrue(crypto.rsaVerify((s1 * s2) % n, (m1 * m2) % n, e, n))
        self.assertTrue(crypto.rsaVerify(crypto.modInverse(s1, n),
                                         crypto.modInverse(m1, n), e, n))


    def testHash(self):
        self.assertEqual(crypto.hash_sha1('abc').encode('hex'),
                         'a9993e364706816aba3e25717850c26c9cd0d89d')

        self.assertEqual(crypto.hash_sha256('abc').encode('hex'),
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410f'
                         'f61f20015ad')

        self.assertEqual(crypto.hash_sha384('abc').encode('hex'),
                        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b6'
                        '05a43ff5bed8086072ba1e7cc2358baeca134c825a7')

        self.assertEqual(crypto.hash_sha512('abc').encode('hex'),
                        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9ee'
                        'ee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d442364'
                        '3ce80e2a9ac94fa54ca49f')

    def testGcd(self):
        self.assertEqual(crypto.gcd(3, 9), 3)
        self.assertEqual(crypto.gcd(4, 10), 2)
        self.assertEqual(crypto.gcd(3, 11), 1)


    def testExtEuclid(self):
        r = crypto.extEuclid(40902, 24140)
        self.assertTrue(r[0] * 40902 + r[1] * 24140 == r[2])
        self.assertEqual(r[2], 34)
        
        self.assertEqual(crypto.extEuclid(3, 9), (1, 0, 3))
        self.assertEqual(crypto.extEuclid(4, 10), (-2, 1, 2))
        self.assertEqual(crypto.extEuclid(3, 11), (4, -1, 1))
        self.assertEqual(crypto.extEuclid(78, 99), (14, -11, 3))

        
    def testModInverse(self):
        self.assertEqual(crypto.modInverse(5, 14), 3)
        self.assertRaises(Exception, crypto.modInverse, (2, 10))


    def testRandom(self):
        r1 = crypto.randomBytes(10)
        self.assertEqual(len(r1), 10)
        r2 = crypto.randomBytes(10)
        self.assertEqual(len(r2), 10)
        self.assertTrue(r1 != r2)


    def testRandomInt(self):
        i = crypto.randomInt(10)
        self.assertTrue(i >= 0)
        self.assertTrue(i <= 10)


    def testRsaGenerate(self):
        crypto.rsaGenerate(1024)


    def testCFB(self):
        key = 'ebb7109b9203ce8570722a947d548913'.decode('hex')
        iv = '4b31d8f203ffc5d6'.decode('hex')
        c = ('347107356c024871153410cb3c87231ac3814599df4e9e5d4bcd21ed5ac5c3e0ea'
             '65d674752c1e16410e84426ceaa2d741ecaa794ceedba347ac64e6909dffb8b995'
             'b1282bcf6e1d6c40d2251e2eda9e0db766ad5ba188a7b6eca241967535e4196152'
             '91725470c6d0c6170f99f812f498327d5bd70230cc759ca56e56b4816c38756b60'
             'eb5ce1ec09c53a069214f079af242904aceb0ee7bcc9e2640e7a34c9aba22697bd'
             '7cc42ac1bcb8c914622f096e8eda6195e18a24ee2c90965d7c7262077977116dfd'
             'b2cc1ae77da9be2437502e44b497d4ec8ae90915e562ecccf66e3b355cfb4ceffa'
             'af86f1d202fd4d6826e77a4d21134f9577895658f65befdf7b9eaf3e98dff19072'
             '658a2ca4b0ab5d859354dd1c7d68c8582e8b53eb884df964de54f87453141ccd7b'
             '712eafbc0d9db4f16880996aab56a39e64258d9cd9f28d9cf7e82396fe0582666e'
             '0215e185d102464ff19ad5fb55ed9f1ea85bd659c91a728ed74bbe56de0fbb7352'
             '1f2c69797a2c692a1b2a4f3a87fd5a9749f37dcd9d00c0e95b21a708e91bddef94'
             'd0e68da26fbbdf4793603e9bd0baa71d77d8e556d7b8f59d8ba544c76574e36d31'
             '015b3ae72ea05e6e2a1d410e1af0ce6b75aa79f8ba84e50caeff68936703485990'
             '54928aecb2443f988be5ac3b0eb9cd87b3448ef24811b928c1b6ec0a7614b25480'
             'aaa530d51b6be969aa386c203a114b9a9679eb1a2d6a3c4f304c69930b2ea76f3d'
             'a6cc53cfea7c76823b259df7174cc58c5c90ac91c570249326197aa336601e052d'
             '25b8de75032e7c4bd71e6a8732501eb12be91190699242e4f2b1aa53c23994bfc7'
             'b7ac6f36e20aca984bf885e943178cf7174336ad0183037d531c4c128f18b8707d'
             'd3b75a308d75ced1c226a1a10d7604d1934721342069d2dc7712fd1c25ab4ed432'
             '4342f6e7db673ffe').decode('hex')
        p = ('07ff654f375aacf466501f4bc069519586cde3cfc5ac36b8167e1055bef9932631'
             'c881852544e2b78b3d56871a330c100195902255625cc8a44b8a26bd98967380df'
             '25f3ac0d80cf0b3be05b17874ad753823f6c8447dee76e1fb1bd78ffec188c6af8'
             'cd1f3f4acb30b4c7fea7766d00a828665aef1c3cfe610d7039f1179900804597fa'
             '411e48b220acbf6f72a710ac0669beee5b6e634578b4e59532ac7b1be45164dd88'
             '80b6f397390ad7f6a0a7db48fe695d8e4a956dcb8d9678b8017a1feb73f224fb7a'
             '9383523b38656cdfdd9462cb4c5efb33d04023ea7b16bfb3a5c9f4e35159a3df0d'
             '9a474b3d4db0bfb6a309facbb52c0b82a5e0e7e6d40b079523c1190400ee7a03e6'
             'ec4e938a8744faa392d79dd9dcbb45a5d14317dbac8f4f8f009a84ed9fe334d993'
             'df4e044fb4d88af1509ffc7b449563f20c5346a08ca397ea7510bcb113069df0bb'
             'dfe84fd81d042f351b1740590a43315c44f6cda43fdce55e61fd633ca116f9f153'
             'ddd41baac427eba7c521f8fc2e9d31510b019de2f81b145a670400f993751c5f58'
             '9d1731b7107759129f950ce18fe40836d648cd526aae001ed27238cd177a95376b'
             '1dda533f361fdb869d86c8c50d18514e09c450621909112ba0c2b12b5b16ce63f6'
             '721b4d550e29abdbbdc0b22abbe3298f9244eef2ab3d7827490a04999c7e1c4525'
             '545a9225e5fff09d63b1f6395cbe80f1e4126593fd4c4f03ff4fd0d21a408b87ab'
             '9181b4754a5c3bb8c63381b3a5307097b5e6151bbeb248d79707f34faac2d02024'
             '20d7f76ea14e55abf8e0613642620076503e644481bf6ff6b6e736b1fe5455da4b'
             '896b50770f67756ea3d65ba026ccf46807ad9d214585a6f883760baef2b4c40c25'
             '08fa8b380a8de16a2900996e3cd793e380ae263f3983e7cbdec37f837bf3659788'
             '6152e9f28a5ae5ec').decode('hex')
        self.assertEqual(crypto.decryptCFB(key, c, iv, crypto.SYMALGORITHM_CAST5),
                         p)
        m = 'Foobarrr'
        key = '1234567890123456'
        iv = '00000000'
        c = crypto.encryptCFB(key, m, iv, crypto.SYMALGORITHM_CAST5)
        self.assertEqual(crypto.decryptCFB(key, c, iv, crypto.SYMALGORITHM_CAST5),
                         m)
        m = 'FoobarrrFoobarrr'
        key = '1234567890123456'
        iv = '00000000'
        c = crypto.encryptCFB(key, m, iv, crypto.SYMALGORITHM_CAST5)
        self.assertEqual(crypto.decryptCFB(key, c, iv, crypto.SYMALGORITHM_CAST5),
                         m)
        m = 'FoobarrrFoobarrr1234'
        key = '1234567890123456'
        iv = '00000000'
        c = crypto.encryptCFB(key, m, iv, crypto.SYMALGORITHM_CAST5)
        self.assertEqual(crypto.decryptCFB(key, c, iv, crypto.SYMALGORITHM_CAST5),
                         m)
        key = '1234567890123456'
        self.assertEqual(crypto.decryptCFB(key, 16*'c', 16*'0',
                                           crypto.SYMALGORITHM_AES128),
                         'f0df6cc895ab3dfd7f30b4ebe6545ea4'.decode('hex'))
        self.assertEqual(crypto.decryptCFB(key, 18*'c', 16*'0',
                                           crypto.SYMALGORITHM_AES128),
                         'f0df6cc895ab3dfd7f30b4ebe6545ea442ec'.decode('hex'))

    def testSymEncryptDecrypt(self):
        m = 'Foobarrr'
        key = '1234567890123456'
        c = crypto.symEncrypt(key, m, crypto.SYMALGORITHM_PLAIN)
        self.assertEqual(m, crypto.symDecrypt(key, c, crypto.SYMALGORITHM_PLAIN))

        c = crypto.symEncrypt(key,m, crypto.SYMALGORITHM_3DES)
        self.assertEqual(m, crypto.symDecrypt(key, c, crypto.SYMALGORITHM_3DES))

        c = crypto.symEncrypt(key,m, crypto.SYMALGORITHM_CAST5)
        self.assertEqual(m, crypto.symDecrypt(key, c, crypto.SYMALGORITHM_CAST5))

        c = crypto.symEncrypt(key,m, crypto.SYMALGORITHM_BLOWFISH)
        self.assertEqual(m, crypto.symDecrypt(key,c,crypto.SYMALGORITHM_BLOWFISH))

        m = 'FoobarrrFoobarrr'
        c = crypto.symEncrypt(key,m, crypto.SYMALGORITHM_AES128)
        self.assertEqual(m, crypto.symDecrypt(key, c, crypto.SYMALGORITHM_AES128))
        self.assertEqual(crypto.symEncrypt(key, 16*'0',
                                           crypto.SYMALGORITHM_AES128),
                         '93bc0fabf6c85e9e1c53d78885373dc7'.decode('hex'))

        key = 24*'a'
        c = crypto.symEncrypt(key,m, crypto.SYMALGORITHM_AES192)
        self.assertEqual(m, crypto.symDecrypt(key, c, crypto.SYMALGORITHM_AES192))

        key = 32*'a'
        c = crypto.symEncrypt(key,m, crypto.SYMALGORITHM_AES256)
        self.assertEqual(m, crypto.symDecrypt(key, c, crypto.SYMALGORITHM_AES256))

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()
