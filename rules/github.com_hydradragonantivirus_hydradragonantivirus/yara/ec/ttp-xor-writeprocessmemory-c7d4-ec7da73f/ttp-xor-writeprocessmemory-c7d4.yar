rule TTP_XOR_WriteProcessMemory_c7d4 {
  strings:
    $key_c7d4 = { 90 a6 [2] a2 84 [2] a4 b1 [2] 8a b1 [2] b5 ad }

  condition:
    any of them
}