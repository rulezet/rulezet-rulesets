rule TTP_XOR_WriteProcessMemory_67c3 {
  strings:
    $key_67c3 = { 30 b1 [2] 02 93 [2] 04 a6 [2] 2a a6 [2] 15 ba }

  condition:
    any of them
}