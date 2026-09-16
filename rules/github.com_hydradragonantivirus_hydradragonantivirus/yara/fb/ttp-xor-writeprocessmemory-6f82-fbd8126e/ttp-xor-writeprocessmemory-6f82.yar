rule TTP_XOR_WriteProcessMemory_6f82 {
  strings:
    $key_6f82 = { 38 f0 [2] 0a d2 [2] 0c e7 [2] 22 e7 [2] 1d fb }

  condition:
    any of them
}