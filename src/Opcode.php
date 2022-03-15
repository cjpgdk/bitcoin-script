<?php
// @codingStandardsIgnoreFile

declare(strict_types=1);

namespace Cjpg\Bitcoin\Script;

use ReflectionClass;

enum Opcode: int 
{
    // bitcoin/src/script/script.h
    // push value
    case OP_0 = 0x00;
    public const OP_FALSE = self::OP_0;
    case OP_PUSHDATA1 = 0x4c;
    case OP_PUSHDATA2 = 0x4d;
    case OP_PUSHDATA4 = 0x4e;
    case OP_1NEGATE = 0x4f;
    case OP_RESERVED = 0x50;
    case OP_1 = 0x51;
    public const OP_TRUE = self::OP_1;
    case OP_2 = 0x52;
    case OP_3 = 0x53;
    case OP_4 = 0x54;
    case OP_5 = 0x55;
    case OP_6 = 0x56;
    case OP_7 = 0x57;
    case OP_8 = 0x58;
    case OP_9 = 0x59;
    case OP_10 = 0x5a;
    case OP_11 = 0x5b;
    case OP_12 = 0x5c;
    case OP_13 = 0x5d;
    case OP_14 = 0x5e;
    case OP_15 = 0x5f;
    case OP_16 = 0x60;

    // control
    case OP_NOP = 0x61;
    case OP_VER = 0x62;
    case OP_IF = 0x63;
    case OP_NOTIF = 0x64;
    case OP_VERIF = 0x65;
    case OP_VERNOTIF = 0x66;
    case OP_ELSE = 0x67;
    case OP_ENDIF = 0x68;
    case OP_VERIFY = 0x69;
    case OP_RETURN = 0x6a;

    // stack ops
    case OP_TOALTSTACK = 0x6b;
    case OP_FROMALTSTACK = 0x6c;
    case OP_2DROP = 0x6d;
    case OP_2DUP = 0x6e;
    case OP_3DUP = 0x6f;
    case OP_2OVER = 0x70;
    case OP_2ROT = 0x71;
    case OP_2SWAP = 0x72;
    case OP_IFDUP = 0x73;
    case OP_DEPTH = 0x74;
    case OP_DROP = 0x75;
    case OP_DUP = 0x76;
    case OP_NIP = 0x77;
    case OP_OVER = 0x78;
    case OP_PICK = 0x79;
    case OP_ROLL = 0x7a;
    case OP_ROT = 0x7b;
    case OP_SWAP = 0x7c;
    case OP_TUCK = 0x7d;

    // splice ops
    case OP_CAT = 0x7e;
    case OP_SUBSTR = 0x7f;
    case OP_LEFT = 0x80;
    case OP_RIGHT = 0x81;
    case OP_SIZE = 0x82;

    // bit logic
    case OP_INVERT = 0x83;
    case OP_AND = 0x84;
    case OP_OR = 0x85;
    case OP_XOR = 0x86;
    case OP_EQUAL = 0x87;
    case OP_EQUALVERIFY = 0x88;
    case OP_RESERVED1 = 0x89;
    case OP_RESERVED2 = 0x8a;

    // numeric
    case OP_1ADD = 0x8b;
    case OP_1SUB = 0x8c;
    case OP_2MUL = 0x8d;
    case OP_2DIV = 0x8e;
    case OP_NEGATE = 0x8f;
    case OP_ABS = 0x90;
    case OP_NOT = 0x91;
    case OP_0NOTEQUAL = 0x92;

    case OP_ADD = 0x93;
    case OP_SUB = 0x94;
    case OP_MUL = 0x95;
    case OP_DIV = 0x96;
    case OP_MOD = 0x97;
    case OP_LSHIFT = 0x98;
    case OP_RSHIFT = 0x99;

    case OP_BOOLAND = 0x9a;
    case OP_BOOLOR = 0x9b;
    case OP_NUMEQUAL = 0x9c;
    case OP_NUMEQUALVERIFY = 0x9d;
    case OP_NUMNOTEQUAL = 0x9e;
    case OP_LESSTHAN = 0x9f;
    case OP_GREATERTHAN = 0xa0;
    case OP_LESSTHANOREQUAL = 0xa1;
    case OP_GREATERTHANOREQUAL = 0xa2;
    case OP_MIN = 0xa3;
    case OP_MAX = 0xa4;

    case OP_WITHIN = 0xa5;

    // crypto
    case OP_RIPEMD160 = 0xa6;
    case OP_SHA1 = 0xa7;
    case OP_SHA256 = 0xa8;
    case OP_HASH160 = 0xa9;
    case OP_HASH256 = 0xaa;
    case OP_CODESEPARATOR = 0xab;
    case OP_CHECKSIG = 0xac;
    case OP_CHECKSIGVERIFY = 0xad;
    case OP_CHECKMULTISIG = 0xae;
    case OP_CHECKMULTISIGVERIFY = 0xaf;

    // expansion
    case OP_NOP1 = 0xb0;
    case OP_CHECKLOCKTIMEVERIFY = 0xb1;
    public const OP_NOP2 = self::OP_CHECKLOCKTIMEVERIFY;
    case OP_CHECKSEQUENCEVERIFY = 0xb2;
    public const OP_NOP3 = self::OP_CHECKSEQUENCEVERIFY;
    case OP_NOP4 = 0xb3;
    case OP_NOP5 = 0xb4;
    case OP_NOP6 = 0xb5;
    case OP_NOP7 = 0xb6;
    case OP_NOP8 = 0xb7;
    case OP_NOP9 = 0xb8;
    case OP_NOP10 = 0xb9;

    // Opcode added by BIP 342 (Tapscript)
    case OP_CHECKSIGADD = 0xba;

    case OP_INVALIDOPCODE = 0xff;

    /**
     * Check if the $value is the same as $code
     * 
     * @param int $value
     * @param Opcode $code
     * @return bool
     */
    public static function valueIs(int $value, Opcode $code): bool
    {
        return $code->value === $value;
    }
    /**
     * Check if opcode is push data
     *
     * @param int $value
     * @return bool
     */
    public static function isPushData(int $value): bool
    {
        return $value >= Opcode::OP_0->value &&
               $value <= Opcode::OP_PUSHDATA4->value;
    }

    /**
     * Check if $value is between OP_0 and OP_PUSHDATA1
     *
     * @param int $value
     * @return bool
     */
    public static function isData(int $value): bool
    {
        // Opcode 1-75 - 0x01-0x4b
        return $value > Opcode::OP_0->value &&
               $value < Opcode::OP_PUSHDATA1->value;
    }

    /**
     * Check if this is a small positive integer opcode
     * OP_1 through OP_16.
     *
     * @return bool
     */
    public function isSmallInteger(): bool
    {
        return $this->value >= Opcode::OP_1->value &&
               $this->value <= Opcode::OP_16->value;
    }

    /**
     * Initialize an Opcode from code.
     * 
     * *Note* if $value is not in the list of OP_x code
     * values the returned OP_INVALIDOPCODE
     *
     * @param int $value
     * @return Opcode
     */
    public static function fromCode(int $value): Opcode
    {
        return self::tryFrom($value) ?? Opcode::OP_INVALIDOPCODE;
    }

    /**
     * Initialize an Opcode from name.
     * 
     * *Note* if $name is not in the list of OP_x code
     * names the returned OP_INVALIDOPCODE.
     *
     * @param string $name
     * @return Opcode
     */
    public static function fromName(string $name): Opcode
    {
        $name = strtoupper($name);
        if ($name == 'OP_FALSE') {
            return Opcode::OP_0;
        }
        if ($name == 'OP_TRUE') {
            return Opcode::OP_1;
        }
        if ($name == 'OP_NOP2') {
            return Opcode::OP_CHECKLOCKTIMEVERIFY;
        }
        if ($name == 'OP_NOP3') {
            return Opcode::OP_CHECKSEQUENCEVERIFY;
        }
        foreach (Opcode::cases() as $case) {
            if($case->name == $name) {
                return $case;
            }
        }
        return Opcode::OP_INVALIDOPCODE;
    }

    /**
     * Decode an OP_n to it's numeric value.
     *
     * @return int if not an OP_0 thru OP_16 the returned value is -1
     */
    public function decode(): int
    {
        if (!($this->value <= Opcode::OP_16->value)) {
            return -1;
        }
        if ($this === Opcode::OP_0) {
            return 0;
        }
        return $this->value - (Opcode::OP_1->value - 1);
    }

    /**
     * Encode a number between 0 and 16 inclusive to an Opcode
     *
     * @param int $n
     * @return Opcode|null Returns null if $n is not a number
     *                     between 0 and 16 inclusive
     */
    public static function encode(int $n): ?Opcode
    {
        if (!($n >= 0 && $n <= 16)) {
            return null;
        }
        // assert($n >= 0 && $n <= 16);
        if ($n == 0) {
            return Opcode::OP_0;
        }
        return Opcode::tryFrom(Opcode::OP_1->value + $n - 1);
    }
}
