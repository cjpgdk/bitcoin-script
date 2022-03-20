<?php

namespace Test;

use Cjpg\Bitcoin\Script\ScriptSig;
use Cjpg\Bitcoin\Script\ScriptPubKey;
use PHPUnit\Framework\TestCase;

final class ScriptTest extends TestCase
{
    public function testScriptPubKey(): void
    {
        $scriptPubKeys = [
            [
                'hex' => '2102a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397ac',
                'asm' => '02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397 OP_CHECKSIG',
                'type' => 'pubkey',
                'type_fn' => 'isPayToPubKey'
            ],
            [
                'hex' => '76a9148fd139bb39ced713f231c58a4d07bf6954d1c20188ac',
                'asm' => 'OP_DUP OP_HASH160 8fd139bb39ced713f231c58a4d07bf6954d1c201 OP_EQUALVERIFY OP_CHECKSIG',
                'type' => 'pubkeyhash',
                'type_fn' => 'isPayToPubKeyHash'
            ],
            [
                'hex' => '522102a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff39721021ac43c7ff740014c3b33737ede99c967e4764553d1b2b83db77c83b8715fa72d2102df2089105c77f266fa11a9d33f05c735234075f2e8780824c6b709415f9fb48553ae',
                'asm' => 'OP_2 02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397 021ac43c7ff740014c3b33737ede99c967e4764553d1b2b83db77c83b8715fa72d 02df2089105c77f266fa11a9d33f05c735234075f2e8780824c6b709415f9fb485 OP_3 OP_CHECKMULTISIG',
                'type' => 'multisig',
                'type_fn' => 'isMultisig'
            ],
            [
                'hex' => '0014a2516e770582864a6a56ed21a102044e388c62e3',
                'asm' => 'OP_0 a2516e770582864a6a56ed21a102044e388c62e3',
                'type' => 'witness_v0_keyhash',
                'type_fn' => 'isPayToWitnessPublicKeyHash'
            ],
            [
                'hex' => 'a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87',
                'asm' => 'OP_HASH160 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee OP_EQUAL',
                'type' => 'scripthash',
                'type_fn' => 'isPayToScriptHash'
            ],
            [
                'hex' => '0020eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                'asm' => 'OP_0 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                'type' => 'witness_v0_scripthash',
                'type_fn' => 'isPayToWitnessScriptHash'
            ],
            [
                'hex' => '51206527a8f262d79e951999dceb68584e93c623e11a5746002c656c63beb71338e3',
                'asm' => 'OP_1 6527a8f262d79e951999dceb68584e93c623e11a5746002c656c63beb71338e3',
                'type' => 'witness_v1_taproot',
                'type_fn' => 'isPayToWitnessTaproot'
            ],
            [
                'hex' => '5120451979076a2ae67ef23c5ef51e3d264e1f572d7ddc60e6fd95e502df009f9674',
                'asm' => 'OP_1 451979076a2ae67ef23c5ef51e3d264e1f572d7ddc60e6fd95e502df009f9674',
                'type' => 'witness_v1_taproot',
                'type_fn' => 'isPayToWitnessTaproot'
            ],
            [
                'hex' => '51202fcad7470279652cc5f88b8908678d6f4d57af5627183b03fc8404cb4e16d889',
                'asm' => 'OP_1 2fcad7470279652cc5f88b8908678d6f4d57af5627183b03fc8404cb4e16d889',
                'type' => 'witness_v1_taproot',
                'type_fn' => 'isPayToWitnessTaproot'
            ],
            [
                'hex' => '5120eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                'asm' => 'OP_1 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                'type' => 'witness_v1_taproot',
                'type_fn' => 'isPayToWitnessTaproot'
            ]
        ];

        foreach ($scriptPubKeys as $scriptPubKey) {
            $script = new ScriptPubKey($scriptPubKey['hex'], true);

            $this->assertSame($scriptPubKey['asm'], "{$script}");
            $this->assertSame($scriptPubKey['type'], $script->getType());
            $this->assertTrue($script->{$scriptPubKey['type_fn']}());

            $this->assertIsArray($script->publicKeyHashes());
            if (
                    in_array($scriptPubKey['type'], [
                        'pubkeyhash', 'witness_v0_keyhash',
                        'witness_v1_taproot', 'scripthash',
                        'witness_v0_scripthash'
                    ])
            ) {
                $this->assertNotEmpty($script->publicKeyHashes());
            } else {
                $this->assertEmpty($script->publicKeyHashes());
            }
        }
    }

    public function testScriptSig(): void
    {
        /*
         * "asm": "3046022100ef794a8ef7fd6752d2a183c18866ff6e8dc0f5bd889a63e2c21cf303a6302461022100c1b09662d9e92988c3f9fcf17d1bcc79b5403647095d7212b9f8a1278a532d68[ALL] 03091137f3ef23f4acfc19a5953a68b2074fae942ad3563ef28c33b0cac9a93adc",
         * "hex": "493046022100ef794a8ef7fd6752d2a183c18866ff6e8dc0f5bd889a63e2c21cf303a6302461022100c1b09662d9e92988c3f9fcf17d1bcc79b5403647095d7212b9f8a1278a532d68012103091137f3ef23f4acfc19a5953a68b2074fae942ad3563ef28c33b0cac9a93adc"
         *
         *
         */
        // i only test that it parses, will add some real tests at some point.
        $scripts = [
            '47304402204D82EC3E691288380EA3F09AD29DB893E7D917D4873076430A39B9B6'
            . 'EB52473702200B6EF42E3F66F60CFD1BCB541759B20B01D55225243EDB99BB040'
            . '7D2AF9D5B6E014104D136B3F27A38333B2158188AA015DFE36FF1C7C62E62B180'
            . 'EF04A720B312A7CA1D25A66E6CDB292F9E8774035E7ECC7EFA89627D61CE0BBF7'
            . 'BB5678801FC6C73',

            '493046022100F14675F6E36E6B43E865C66A697639B52F2544EFE6EB7E94D02057'
            . '2EC1AF00E6022100C176CF510210CECCCB4C8DD248A66F44679394F57EF6865C3'
            . 'E9133B111861A0701',

            /*
             * This is properly the best script to test that it works.
             * tx c705ec760f828063461630048d7e372005a6dc9cba054b1524bf469eb3117de4
             */
            '0048304502200f2b7f85fdc8454b7fe498496386625fc1dfcee59bcd5f2d7681a1'
            . 'c3f2d88c9f022100c102247446a5d3fd5bd3c414144233eafcc991a6a45686b97'
            . '4c375888a1f43b40147304402203965594980be73ba5377919849bd834e1fd30d'
            . '7b836bd8ff8ffad7c7dd7678af02205b96e4b23a52de236c6648c754ff3c3a391'
            . '22a62fa00e8c80d3928fb5e465d160148304502205dd601389315f2b8ec74c28a'
            . 'fa2c6fb9bffbc8882cc6462abe3c8de1dcfd4593022100c1768d9df9a39f71e8f'
            . '5af968fb660dc53b59b5d932c90dcb156f953bb751a960147304402206ba457c1'
            . '8ab22b2976084c326435b7f13ec2553d4205827f84ef8fb2839b060202206d4d8'
            . '16feda334bd2daec0597bba20b5ab1a0e8781a9156c0e5034a234966128014930'
            . '46022100b9a813028493ae0cc81fbdb18c52d9de43e27ed38c1a7bf4ee0e6f4b7'
            . '202e56e022100ebd9b77812963460fe0049a073391beea42f4dd8bef822386110'
            . 'f6b7e0695bb201483045022100f27648f83b6c7accfad41163f67ffbb2c81616b'
            . '15ebf7f650e5617a9d88bea9d02206912d3f7a111256bfb930398266d7c85f935'
            . '7bd9c3d98bb7efed5d392c40238b0147304402207ec83616ef710f1382c1903cb'
            . 'f38760c5c0e5a86025db03496eabe3e876abecb022063c7989574e69dea32e930'
            . '0b07feaa6dc77e567bda2781d13432f0472da07e7a01483045022076cc1e5d250'
            . '4fc1125d9d22607c7814aeeb7e5a148abbc199533759bff4b0c44022100e1e0a3'
            . '0b6631fbd627061592d7d26e122263bfbad41480644c905784fc348805014d350'
            . '1582102571822b55f780e05b247f13b7701b13db07cab446d40e6ce9dc1260396'
            . '2c434d2102190b681930fdf0e8db3df5dd31a99db715195ac6b3b1df4d4c6d074'
            . '5e61799f72103637257dd3fd1e30d81782e3fd2b8da243fd886592604b0444180'
            . 'a536f4a8bbd721032d862f482cb6ec52b96d86fb991e4a6a5198a53a5740fed36'
            . '8e14dee13229d482102e555d19d8cdca9f71df6af66255c6e2dff765007ba898b'
            . '37eccea7726c22b9202102f8b2286342c1ad1d5ea5619e2217623be74b232b5d6'
            . '20e102c2c43f4bb0ce82f21034b27f9a42ec036d8eb17d6d746072f0fdad49dfa'
            . 'bacb80a605beed70584f15c7210355cd84c5a46468ebd77b4fc997c7e35cef6fb'
            . 'f5b74190aee2736d8826388cdfb210351bd8b2d93829e09b75b388088ea33478b'
            . 'cff4821b05a22486fb12027ef2189459ae',

            '30450221008163c18ff109378b4699582c58a251466084bc80e3c388838065e1b5'
            . '776a2dc9022070c28f001f677f07edc4260679642a68ce5bfc732daab607cb0f9'
            . '09e7bdb6c4201026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a62'
            . '1ef65f177ea286',
        ];

        foreach ($scripts as $key => $script) {
            $script = strtolower($script);
            $scriptSig = new ScriptSig($script, true);

            $this->assertSame($script, $scriptSig->toHex());
            $this->assertIsArray($scriptSig->parse());
            $this->assertNotEmpty($scriptSig->parse());
            $this->assertNotEmpty((string)$scriptSig);
        }
    }
}
