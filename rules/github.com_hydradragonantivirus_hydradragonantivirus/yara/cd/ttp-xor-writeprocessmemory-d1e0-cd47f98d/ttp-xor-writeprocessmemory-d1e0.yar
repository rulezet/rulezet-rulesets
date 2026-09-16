rule TTP_XOR_WriteProcessMemory_d1e0 {
  strings:
    $key_d1e0 = { 86 92 [2] b4 b0 [2] b2 85 [2] 9c 85 [2] a3 99 }

  condition:
    any of them
}