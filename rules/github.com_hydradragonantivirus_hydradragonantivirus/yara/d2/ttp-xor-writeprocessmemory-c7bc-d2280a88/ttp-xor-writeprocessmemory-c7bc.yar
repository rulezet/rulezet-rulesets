rule TTP_XOR_WriteProcessMemory_c7bc {
  strings:
    $key_c7bc = { 90 ce [2] a2 ec [2] a4 d9 [2] 8a d9 [2] b5 c5 }

  condition:
    any of them
}