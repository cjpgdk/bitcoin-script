<?php

declare(strict_types=1);

namespace Cjpg\Bitcoin\Script;

/**
 * class Op is a script operation.
 */
class Op
{
    /**
     * @var Opcode
     */
    public $code;

    /**
     * @var string|null
     */
    public $data;

    /**
     * Initialize a new instance of Op class.
     *
     * @param Opcode $code
     * @param string|null $data
     */
    public function __construct(Opcode $code, ?string $data = null)
    {
        $this->code = $code;
        $this->data = $data;
    }

    /**
     * Get the size of the data.
     *
     * @return int
     */
    public function size(): int
    {
        return $this->data == null ? 0 : strlen($this->data);
    }

    /**
     * Get data of this operation as a hexadecimal
     *
     * @return string
     */
    public function hex(): string
    {
        return bin2hex($this->data ?: '');
    }

    /**
     * Convert the Operation to a string.
     *
     * @return string
     */
    public function __toString()
    {
        $code = $this->code;
        if ($code >= Opcode::OP_PUSHDATA1 && $code <= Opcode::OP_PUSHDATA4) {
            // OP_PUSHDATA1
            if ($code >= Opcode::OP_PUSHDATA1 && $code < Opcode::OP_PUSHDATA2) {
                return sprintf('OP_PUSHDATA1 %s', $this->hex());
            }
            // OP_PUSHDATA2
            if ($code >= Opcode::OP_PUSHDATA2 && $code < Opcode::OP_PUSHDATA4) {
                return sprintf('OP_PUSHDATA2 %s', $this->hex());
            }
            // OP_PUSHDATA4
            return sprintf('OP_PUSHDATA4 %s', $this->hex());
        }

        if (
            !Opcode::isData($this->code->value) &&
            $this->code !== Opcode::OP_INVALIDOPCODE
        ) {
            return $this->code->name;
        }
        return $this->hex();
    }
}
