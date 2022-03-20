<?php

declare(strict_types=1);

namespace Cjpg\Bitcoin\Script;

/**
 * class ScriptPubKey
 */
class ScriptPubKey extends Script
{
    /**
     * Get the script type.
     *
     * @return string
     */
    public function getType(): string
    {
        $version = $program = -1;
        if ($this->isWitnessProgram($version, $program)) {
            // TxoutType::WITNESS_V0_KEYHASH isPayToWitnessPublicKeyHash()
            if ($version == 0 && $program == static::WITNESS_V0_KEYHASH_SIZE) {
                return "witness_v0_keyhash";
            }
            // TxoutType::WITNESS_V0_SCRIPTHASH isPayToWitnessScriptHash()
            if ($version == 0 && $program == static::WITNESS_V0_SCRIPTHASH_SIZE) {
                return "witness_v0_scripthash";
            }
            // TxoutType::WITNESS_V1_TAPROOT isPayToWitnessTaproot()
            if ($version == 1 && $program == static::WITNESS_V1_TAPROOT_SIZE) {
                return "witness_v1_taproot";
            }
            // TxoutType::WITNESS_UNKNOWN
            if ($version != -1) {
                return "witness_unknown";
            }
        }
        // TxoutType::MULTISIG
        if ($this->isMultisig()) {
            return "multisig";
        }
        // TxoutType::PUBKEY
        if ($this->isPayToPubKey()) {
            return "pubkey";
        }
        //TxoutType::PUBKEYHASH
        if ($this->isPayToPubKeyHash()) {
            return "pubkeyhash";
        }
        // TxoutType::SCRIPTHASH
        if ($this->isPayToScriptHash()) {
            return "scripthash";
        }
        // TxoutType::NULL_DATA
        if ($this->isNullData()) {
            return "nulldata";
        }
        // TxoutType::NONSTANDARD
        return "nonstandard";
    }

    /**
     * Check if this script is null data.
     *
     * @return bool
     */
    public function isNullData(): bool
    {
        return $this->size() >= 1 &&
            Opcode::valueIs(ord($this[0]), Opcode::OP_RETURN) &&
            $this->isPushOnly();
    }

    /**
     * Check if this script is a witness program
     *
     * @param int $version between 0 and 16 inclusive
     * @param int $program the length of the data.
     * @return bool
     */
    public function isWitnessProgram(int &$version, int &$program): bool
    {
        if ($this->size() < 4 || $this->size() > 42) {
            return false;
        }
        $c0 = Opcode::fromCode(ord($this[0]));
        if (
            $c0 != Opcode::OP_0 &&
            ($c0 < Opcode::OP_1 || $c0 > Opcode::OP_16)
        ) {
            return false;
        }

        $c1 = ord($this[1]);
        if (($c1 + 2) == $this->size()) {
            $version = $c0->decode();
            $program = strlen(substr($this->data, 2));
            return true;
        }
        return false;
    }

    /**
     * Pay to witness tap root (P2TR)
     *
     * @return bool
     */
    public function isPayToWitnessTaproot(): bool
    {
        return (
            $this->size() == 34 &&
            Opcode::valueIs(ord($this[0]), Opcode::OP_1) &&
            bin2hex($this[1]) == "20"
        );
    }

    /**
     * Pay to witness public key hash (P2WPKH)
     *
     * @return bool
     */
    public function isPayToWitnessPublicKeyHash(): bool
    {
        return $this->size() == 22 &&
            Opcode::valueIs(ord($this[0]), Opcode::OP_0);
    }

    /**
     * Check if the script is a multisig
     *
     * @param int|null $min [Optional] Outputs the minimum required signatures.
     * @param int|null $max [Optional] Outputs the maximum required signatures.
     * @return bool
     */
    public function isMultisig(?int &$min = null, ?int &$max = null): bool
    {
        if ($this->size() <= 0) {
            return false;
        }

        if (
            !Opcode::fromCode(ord($this[0]))->isSmallInteger() ||
            !Opcode::fromCode(ord($this[-2]))->isSmallInteger()
        ) {
            return false;
        }

        $code = ord($this[-1]);
        if (
            !Opcode::valueIs($code, Opcode::OP_CHECKMULTISIG) &&
            !Opcode::valueIs($code, Opcode::OP_CHECKMULTISIGVERIFY)
        ) {
            return false;
        }
        $min = Opcode::fromCode(ord($this[0]))->decode();
        $max = Opcode::fromCode(ord($this[-2]))->decode();
        return $min <= $max;
    }

    /**
     * Pay to public key (P2PK)
     *
     * @return bool
     */
    public function isPayToPubKey(): bool
    {
        // check size.
        $len = $this->size() > 0 ? ord($this[0]) : 0;
        if ($len != 33 && $len != 65) {
            return false;
        }

        // OP_CHECKSIG | OP_CHECKSIGVERIFY
        $cn1 = ord($this[-1]);
        if (
            !Opcode::valueIs($cn1, Opcode::OP_CHECKSIG) &&
            !Opcode::valueIs($cn1, Opcode::OP_CHECKSIGVERIFY)
        ) {
            return false;
        }

        // pub key prefix
        return (
            $this[1] == "\x04" ||
            $this[1] == "\x02" ||
            $this[1] == "\x03"
        );
    }

    /**
     * Pay to public key hash (P2PKH)
     *
     * @return bool
     */
    public function isPayToPubKeyHash(): bool
    {
        return (
            $this->size() == 25 &&
            Opcode::valueIs(ord($this[0]), Opcode::OP_DUP) &&
            Opcode::valueIs(ord($this[1]), Opcode::OP_HASH160) &&
            Opcode::valueIs(ord($this[23]), Opcode::OP_EQUALVERIFY) &&
            Opcode::valueIs(ord($this[24]), Opcode::OP_CHECKSIG)
        );
    }

    /**
     * Pay to script hash (P2SH)
     *
     * @return bool
     */
    public function isPayToScriptHash(): bool
    {
        return (
            $this->size() == 23 &&
            Opcode::valueIs(ord($this[0]), Opcode::OP_HASH160) &&
            bin2hex($this[1]) == '14' &&
            Opcode::valueIs(ord($this[22]), Opcode::OP_EQUAL)
        );
    }

    /**
     * Pay to witness script hash (P2WSH)
     *
     * @return bool
     */
    public function isPayToWitnessScriptHash(): bool
    {
        return (
            $this->size() == 34 &&
            Opcode::valueIs(ord($this[0]), Opcode::OP_0) &&
            bin2hex($this[1]) == '20'
        );
    }
}
