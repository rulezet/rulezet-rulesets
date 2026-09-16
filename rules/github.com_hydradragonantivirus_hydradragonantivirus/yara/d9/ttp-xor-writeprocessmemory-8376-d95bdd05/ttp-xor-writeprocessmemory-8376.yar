rule TTP_XOR_WriteProcessMemory_8376 {
  strings:
    $key_8376 = { d4 04 [2] e6 26 [2] e0 13 [2] ce 13 [2] f1 0f }

  condition:
    any of them
}