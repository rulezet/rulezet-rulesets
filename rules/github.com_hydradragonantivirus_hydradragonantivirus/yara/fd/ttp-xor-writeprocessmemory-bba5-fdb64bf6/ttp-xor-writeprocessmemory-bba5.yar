rule TTP_XOR_WriteProcessMemory_bba5 {
  strings:
    $key_bba5 = { ec d7 [2] de f5 [2] d8 c0 [2] f6 c0 [2] c9 dc }

  condition:
    any of them
}