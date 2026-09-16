rule TTP_XOR_WriteProcessMemory_61a0 {
  strings:
    $key_61a0 = { 36 d2 [2] 04 f0 [2] 02 c5 [2] 2c c5 [2] 13 d9 }

  condition:
    any of them
}