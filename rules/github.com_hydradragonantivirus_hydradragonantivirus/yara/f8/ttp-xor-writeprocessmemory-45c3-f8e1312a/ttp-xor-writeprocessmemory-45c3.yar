rule TTP_XOR_WriteProcessMemory_45c3 {
  strings:
    $key_45c3 = { 12 b1 [2] 20 93 [2] 26 a6 [2] 08 a6 [2] 37 ba }

  condition:
    any of them
}