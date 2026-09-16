rule TTP_XOR_WriteProcessMemory_3346 {
  strings:
    $key_3346 = { 64 34 [2] 56 16 [2] 50 23 [2] 7e 23 [2] 41 3f }

  condition:
    any of them
}