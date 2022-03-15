<?php

declare(strict_types=1);

namespace Cjpg\Bitcoin\Script;

use Cjpg\Bitcoin\Script\Exceptions\ScriptException;
use JsonSerializable;
use ArrayAccess;
use Exception;

/**
 * class Script
 *
 * @implements \ArrayAccess<int, string>
 */
abstract class Script implements JsonSerializable, ArrayAccess
{
    /**
     * The size of witness program v0 key hash
     */
    public const WITNESS_V0_KEYHASH_SIZE = 20;

    /**
     * The size of witness program v0 script hash
     */
    public const WITNESS_V0_SCRIPTHASH_SIZE = 32;

    /**
     * The size of witness program v1 taproot
     */
    public const WITNESS_V1_TAPROOT_SIZE = 32;

    /**
     * The script as a binary string.
     *
     * @var string
     */
    protected $data;

    /**
     * The data reader position.
     *
     * @var int
     */
    protected $pos;

    /**
     * The operations of this script.
     *
     * @var array<Op>
     * @see \Cjpg\Bitcoin\Script\Script::parse()
     */
    protected $ops = [];

    final public function __construct(string $data, bool $isHex = false)
    {
        $fh = null;
        if ($isHex && ($fh = hex2bin($data)) === false) {
            throw new ScriptException("Unable to decode data from hexadecimal");
        }
        $this->data = $fh ?: $data;
    }

    /**
     * Get the size of the script
     *
     * @return int
     */
    public function size(): int
    {
        return strlen($this->data);
    }

    /**
     * Get the script as a binary string.
     *
     * @return string
     */
    public function toBinary(): string
    {
        return $this->data;
    }

    /**
     * Get the script as a hexadecimal string.
     *
     * @return string
     */
    public function toHex(): string
    {
        return bin2hex($this->data);
    }

    /**
     * Init from a hexadecimal string
     *
     * @param string $hex
     * @return static
     */
    public static function fromHex(string $hex): self
    {
        return new static($hex, true);
    }

    /**
     * Gets / parses the current script.
     *
     * @return array<Op>
     * @throws \Cjpg\Bitcoin\Script\Exceptions\ScriptException
     */
    public function parse(): array
    {
        if (!empty($this->ops)) {
            return $this->ops;
        }

        try {
            $this->ops = $this->parseOps();
        } catch (Exception $ex) {
            throw new ScriptException('Parse error.' /* ('.$this->toHex().')*/, $ex->getCode(), $ex);
        }

        return $this->ops;
    }

    /**
     * Parse the script into ops
     *
     * @return array<Op>
     */
    protected function parseOps(): array
    {
        $ops = [];
        $this->pos = 0;

        while ($this->pos < $this->size()) {
            $code = ord($this->data[$this->pos++]);
            $opcode = Opcode::fromCode($code);
            $data = null;
            if ($opcode == Opcode::OP_0) {
                $data = '';
            } elseif (Opcode::isData($code)) {
                $data = $this->readData($code);
            } elseif (Opcode::isPushData($code)) {
                $data = $this->readPushData($opcode);
            } elseif ($opcode == Opcode::OP_1NEGATE) {
                $data = chr(-1);
            }
            $ops[] = new Op($opcode, $data);
        }
        return $ops;
    }

    /**
     * heck if this script is push only.
     *
     * @return bool
     */
    public function isPushOnly(): bool
    {
        for ($i = 1; $i < count($ops = $this->parse()); $i++) {
            if ($ops[$i]->code > Opcode::OP_16) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get the public keys in the script if any.
     *
     * **Note** that the public keys are not validated they are only check for
     * length 33 or 65 and starts with 04, 03 or 02
     *
     * @return array<string>
     */
    public function publicKeys(): array
    {
        $keys = [];
        foreach ($this->parse() as $idx => $op) {
            if (!$op->data || !in_array($op->size(), [33, 65])) {
                continue;
            }

            if (!in_array($op->data[0], ["\x04", "\x03", "\x02"])) {
                continue;
            }
            $keys[] = $op->hex();
        }

        return $keys;
    }

    /**
     * Reads push data (0x01-0x4b)
     *
     * @param int $code
     * @return string
     */
    private function readData(int $code): string
    {
        /*
         * Check that we actually can read this amount of data!
         * do not remember tx but one out their is well wrong!
         */
        if (($this->pos + $code) > $this->size()) {
            $data = substr($this->data, $this->pos, $this->size() - $this->pos);
            $this->pos += $this->size() - $this->pos;
        } else {
            $data = substr($this->data, $this->pos, $code);
            $this->pos += $code;
        }

        return $data;
    }

    /**
     * Reads push data (OP_PUSHDATA1, OP_PUSHDATA2 and OP_PUSHDATA4)
     *
     * @param Opcode $code
     * @return string
     */
    private function readPushData(Opcode $code): string
    {
        $read = ord($this[$this->pos]);

        if (Opcode::OP_PUSHDATA2 == $code) {
            $read = $this->swapEndianness(
                substr($this->data, $this->pos, 2)
            );
            $this->pos += 2;
        } elseif (Opcode::OP_PUSHDATA4 == $code) {
            $read = $this->swapEndianness(
                substr($this->data, $this->pos, 4)
            );
            $this->pos += 4;
        } else {
            $this->pos += 1;
        }

        $data = substr($this->data, $this->pos, $read);
        $this->pos += $read;
        return $data;
    }

    /**
     * Swap endianness.
     *
     * @param string $bin
     * @return int
     */
    private function swapEndianness(string $bin): int
    {
        $bin = bin2hex($bin);
        $pack = pack("H*", $bin);
        if ($unpack = unpack("H*", strrev($pack))) {
            return (int)hexdec($unpack[1]);
        }
        return 0;
    }

    /**
     * Check if offset  exists.
     *
     * @param int $offset
     * @return bool
     */
    public function offsetExists($offset): bool
    {
        return $offset <= ($this->size() - 1);
    }

    /**
     * Get the item at $offset.
     *
     * @param int $offset
     * @return string Binary string at offset.
     */
    #[\ReturnTypeWillChange]
    public function offsetGet($offset): string
    {
        return $this->data[$offset];
    }

    /**
     * Set/Add an item.
     *
     * @param int $offset
     * @param string $value A single byte binary string to set at offset.
     * @return void
     */
    public function offsetSet($offset, $value): void
    {
        $this->data[$offset] = $value;
    }

    /**
     * Unset an item from the list.
     *
     * @param int $offset
     * @return void
     */
    public function offsetUnset($offset): void
    {
        unset($this->data[$offset]);
    }



    public function __toString()
    {
        return implode(' ', $this->parse());
    }

    public function jsonSerialize(): string
    {
        return $this->__toString();
    }
}
