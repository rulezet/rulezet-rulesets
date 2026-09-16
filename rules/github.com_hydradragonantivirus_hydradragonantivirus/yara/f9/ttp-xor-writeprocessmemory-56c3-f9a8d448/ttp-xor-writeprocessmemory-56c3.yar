rule TTP_XOR_WriteProcessMemory_56c3 {
  strings:
    $key_56c3 = { 01 b1 [2] 33 93 [2] 35 a6 [2] 1b a6 [2] 24 ba }

  condition:
    any of them
}