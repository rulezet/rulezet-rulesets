rule TTP_XOR_WriteProcessMemory_8fad {
  strings:
    $key_8fad = { d8 df [2] ea fd [2] ec c8 [2] c2 c8 [2] fd d4 }

  condition:
    any of them
}