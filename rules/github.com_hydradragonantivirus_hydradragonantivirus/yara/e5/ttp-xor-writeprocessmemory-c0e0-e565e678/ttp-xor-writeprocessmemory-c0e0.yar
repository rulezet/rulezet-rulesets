rule TTP_XOR_WriteProcessMemory_c0e0 {
  strings:
    $key_c0e0 = { 97 92 [2] a5 b0 [2] a3 85 [2] 8d 85 [2] b2 99 }

  condition:
    any of them
}