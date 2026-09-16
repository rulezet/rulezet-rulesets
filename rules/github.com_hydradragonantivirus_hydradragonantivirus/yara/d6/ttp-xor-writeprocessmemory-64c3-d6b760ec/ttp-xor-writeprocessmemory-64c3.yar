rule TTP_XOR_WriteProcessMemory_64c3 {
  strings:
    $key_64c3 = { 33 b1 [2] 01 93 [2] 07 a6 [2] 29 a6 [2] 16 ba }

  condition:
    any of them
}