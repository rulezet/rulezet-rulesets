rule TTP_XOR_WriteProcessMemory_bbba {
  strings:
    $key_bbba = { ec c8 [2] de ea [2] d8 df [2] f6 df [2] c9 c3 }

  condition:
    any of them
}