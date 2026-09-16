rule TTP_XOR_WriteProcessMemory_bdb3 {
  strings:
    $key_bdb3 = { ea c1 [2] d8 e3 [2] de d6 [2] f0 d6 [2] cf ca }

  condition:
    any of them
}