rule TTP_XOR_WriteProcessMemory_c4e0 {
  strings:
    $key_c4e0 = { 93 92 [2] a1 b0 [2] a7 85 [2] 89 85 [2] b6 99 }

  condition:
    any of them
}