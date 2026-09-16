rule TTP_XOR_WriteProcessMemory_d7bc {
  strings:
    $key_d7bc = { 80 ce [2] b2 ec [2] b4 d9 [2] 9a d9 [2] a5 c5 }

  condition:
    any of them
}