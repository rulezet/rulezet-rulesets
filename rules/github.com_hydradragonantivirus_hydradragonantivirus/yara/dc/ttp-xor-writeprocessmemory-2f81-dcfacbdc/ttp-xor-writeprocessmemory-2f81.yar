rule TTP_XOR_WriteProcessMemory_2f81 {
  strings:
    $key_2f81 = { 78 f3 [2] 4a d1 [2] 4c e4 [2] 62 e4 [2] 5d f8 }

  condition:
    any of them
}