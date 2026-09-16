rule TTP_XOR_WriteProcessMemory_41c3 {
  strings:
    $key_41c3 = { 16 b1 [2] 24 93 [2] 22 a6 [2] 0c a6 [2] 33 ba }

  condition:
    any of them
}