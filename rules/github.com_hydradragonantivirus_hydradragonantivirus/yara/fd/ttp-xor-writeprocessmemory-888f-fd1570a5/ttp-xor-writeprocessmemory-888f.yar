rule TTP_XOR_WriteProcessMemory_888f {
  strings:
    $key_888f = { df fd [2] ed df [2] eb ea [2] c5 ea [2] fa f6 }

  condition:
    any of them
}