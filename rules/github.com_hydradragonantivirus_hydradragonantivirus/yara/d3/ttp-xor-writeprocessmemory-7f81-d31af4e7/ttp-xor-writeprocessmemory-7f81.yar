rule TTP_XOR_WriteProcessMemory_7f81 {
  strings:
    $key_7f81 = { 28 f3 [2] 1a d1 [2] 1c e4 [2] 32 e4 [2] 0d f8 }

  condition:
    any of them
}