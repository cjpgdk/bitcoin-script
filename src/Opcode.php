<?php

declare(strict_types=1);

namespace Cjpg\Bitcoin\Script;

use ReflectionClass;

/**
 * class Opcode, an enum like structure for Opcodes.
 *
 * @property-read bool $isSmallInteger Test for "small positive integer" script opcodes - OP_1 through OP_16.
 * @property-read bool $isData Check if $code is between OP_0 and OP_PUSHDATA1
 * @property-read bool $isPushData Check if opcode is push data
 * @property-read int $decodeOpN Decode an OP_n to it's numeric value.
 * @property-read string $getOpName Get a human readable representation of an opcode value.
 */
class Opcode implements IOpcodeType
{
    /**
     * A cached array of opcode names from Opcode::const values.
     *
     * @var array<string, int>
     */
    private static $opcodes = [];

    /**
     * The value of this opcode.
     *
     * @var int
     */
    private $value;

    /**
     * The name of this opcode.
     *
     * @var string
     */
    private $name;

    /**
     * Initialize an Opcode object from code.
     *
     * @param int $code
     * @return void
     */
    protected function __construct(int $code)
    {
        $this->value = $code;
        $this->name = static::getOpName($this->value);
    }

    /**
     * Get the code of the opcode.
     *
     * @return int
     */
    public function code(): int
    {
        return $this->value;
    }

    /**
     * Get the name of the opcode.
     *
     * @return string
     * @see \Cjpg\Bitcoin\Script\Opcode::getOpName($code)
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Initialize an Opcode object from code.
     *
     * @param int $code
     * @return self
     */
    public static function fromCode(int $code): self
    {
        return new self($code);
    }

    /**
     * Initialize an Opcode from name.
     *
     * @param string $name
     * @return self
     */
    public static function fromName(string $name): self
    {
        // ensure op codes are loaded.
        static::getOpcodes();

        $code = isset(self::$opcodes[strtoupper($name)]) ?
                       self::$opcodes[strtoupper($name)] :
                       PHP_INT_MAX;

        return new self($code);
    }

    /**
     * Test for "small positive integer" script opcodes - OP_1 through OP_16.
     *
     * @param int|static $code
     * @return bool
     */
    public static function isSmallInteger($code): bool
    {
        if ($code instanceof static) {
            return $code->isSmallInteger;
        }
        // src/script/standard.cpp:91
        return $code >= static::OP_1 && $code <= static::OP_16;
    }

    /**
     * Check if $code is between OP_0 and OP_PUSHDATA1
     *
     * @param int|static $code
     * @return bool
     */
    public static function isData($code): bool
    {
        if ($code instanceof static) {
            return $code->isData;
        }
        // Opcode 1-75 - 0x01-0x4b
        return $code > static::OP_0 && $code < static::OP_PUSHDATA1;
    }

    /**
     * Check if $code is push data
     *
     * @param int|static $code
     * @return bool
     */
    public static function isPushData($code): bool
    {
        if ($code instanceof static) {
            return $code->isPushData;
        }
        // src/script/standard.cpp:96
        return $code >= static::OP_FALSE && $code <= static::OP_PUSHDATA4;
    }

    /**
     * Get a human readable representation of an opcode value.
     *
     * @param int|static $code
     * @return string
     */
    public static function getOpName($code): string
    {
        if ($code instanceof static) {
            return $code->getOpName;
        }
        $key = array_search($code, static::getOpcodes(), true);
        if ($key !== false) {
            return $key;
        }
        return "OP_UNKNOWN";
    }

    /**
     * Get the opcode as an array.
     *
     * @return array<string, int>
     */
    public static function getOpcodes(): array
    {
        if (empty(self::$opcodes)) {
            $refl = new ReflectionClass(IOpcodeType::class);
            /**
             * we know the constants
             * are string by name and int by value!
             * @phpstan-ignore-next-line
             */
            self::$opcodes = $refl->getConstants();
        }
        /** @phpstan-ignore-next-line ^same as above^. */
        return self::$opcodes;
    }

    /**
     * Decode an OP_n to it's numeric value.
     *
     * @param static|int $code
     * @return int
     */
    public static function decodeOpN($code): int
    {
        if ($code instanceof static) {
            return $code->decodeOpN;
        }
        if ($code == static::OP_0) {
            return 0;
        }
        // assert(opcode >= OP_1 && opcode <= OP_16);
        return $code - (static::OP_1 - 1);
    }

    /**
     * Encode a number between 0 and 16 inclusive to an Opcode
     *
     * @param int $n
     * @return self
     */
    public static function encodeOpN(int $n): self
    {
        // assert($n >= 0 && $n <= 16);
        if ($n == 0) {
            return new self(static::OP_0);
        }
        return new self(static::OP_1 + $n - 1);
    }

    /**
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        $m = strtolower($name);

        // bool isSmallInteger($code)
        if ($m === 'decodeopn') {
            return static::decodeOpN($this->value);
        }

        // bool isSmallInteger($code)
        if ($m === 'issmallinteger') {
            return static::isSmallInteger($this->value);
        }

        // bool isData($code)
        if ($m === 'isdata') {
            return static::isData($this->value);
        }

        // bool isPushData($code)
        if ($m === 'ispushdata') {
            return static::isPushData($this->value);
        }

        // string getOpName(int|string $code)
        if ($m === 'getopname') {
            return $this->name();
        }

        // allow read of $value and name.
        // this is to make them readonly!
        return $this->$name;
    }

    /**
     * Class to opcode name.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->name;
    }
}
