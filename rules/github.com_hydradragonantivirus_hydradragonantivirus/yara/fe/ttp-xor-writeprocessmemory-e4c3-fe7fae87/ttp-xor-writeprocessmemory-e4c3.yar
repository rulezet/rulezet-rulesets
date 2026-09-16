rule TTP_XOR_WriteProcessMemory_e4c3 {
  strings:
    $key_e4c3 = { b3 b1 [2] 81 93 [2] 87 a6 [2] a9 a6 [2] 96 ba }

  condition:
    any of them
}