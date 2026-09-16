rule TTP_XOR_WriteProcessMemory_a7bc {
  strings:
    $key_a7bc = { f0 ce [2] c2 ec [2] c4 d9 [2] ea d9 [2] d5 c5 }

  condition:
    any of them
}