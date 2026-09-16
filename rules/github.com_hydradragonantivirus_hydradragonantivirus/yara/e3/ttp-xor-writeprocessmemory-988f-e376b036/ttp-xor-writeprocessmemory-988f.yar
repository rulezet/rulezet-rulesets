rule TTP_XOR_WriteProcessMemory_988f {
  strings:
    $key_988f = { cf fd [2] fd df [2] fb ea [2] d5 ea [2] ea f6 }

  condition:
    any of them
}