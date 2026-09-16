rule TTP_XOR_WriteProcessMemory_d4e0 {
  strings:
    $key_d4e0 = { 83 92 [2] b1 b0 [2] b7 85 [2] 99 85 [2] a6 99 }

  condition:
    any of them
}