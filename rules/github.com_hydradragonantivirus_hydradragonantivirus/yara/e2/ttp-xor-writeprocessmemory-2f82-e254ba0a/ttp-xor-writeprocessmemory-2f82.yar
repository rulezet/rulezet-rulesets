rule TTP_XOR_WriteProcessMemory_2f82 {
  strings:
    $key_2f82 = { 78 f0 [2] 4a d2 [2] 4c e7 [2] 62 e7 [2] 5d fb }

  condition:
    any of them
}