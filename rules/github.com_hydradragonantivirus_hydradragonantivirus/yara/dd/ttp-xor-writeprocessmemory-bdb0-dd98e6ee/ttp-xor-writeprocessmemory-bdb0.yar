rule TTP_XOR_WriteProcessMemory_bdb0 {
  strings:
    $key_bdb0 = { ea c2 [2] d8 e0 [2] de d5 [2] f0 d5 [2] cf c9 }

  condition:
    any of them
}