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
        if ($this->size() > 0 && Opcode::isPushData($this->code->value)) {
            return $this->hex();
        }

        if ($this->code !== Opcode::OP_INVALIDOPCODE) {
            if($this->code->isSmallInteger() || $this->code == Opcode::OP_0) {
                return (string)$this->code->decode();
            }
            return $this->code->name;
        }
        
       
        if ($this->size() <= 0 && $this->code === Opcode::OP_INVALIDOPCODE) {
            return 'OP_UNKNOWN';
        }
        
        return $this->hex();
    }
}
