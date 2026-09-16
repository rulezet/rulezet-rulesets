rule TTP_XOR_WriteProcessMemory_d646 {
  strings:
    $key_d646 = { 81 34 [2] b3 16 [2] b5 23 [2] 9b 23 [2] a4 3f }

  condition:
    any of them
}