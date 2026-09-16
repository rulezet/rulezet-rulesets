rule TTP_XOR_WriteProcessMemory_71c3 {
  strings:
    $key_71c3 = { 26 b1 [2] 14 93 [2] 12 a6 [2] 3c a6 [2] 03 ba }

  condition:
    any of them
}