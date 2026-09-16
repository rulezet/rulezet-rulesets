rule TTP_XOR_WriteProcessMemory_be8f {
  strings:
    $key_be8f = { e9 fd [2] db df [2] dd ea [2] f3 ea [2] cc f6 }

  condition:
    any of them
}