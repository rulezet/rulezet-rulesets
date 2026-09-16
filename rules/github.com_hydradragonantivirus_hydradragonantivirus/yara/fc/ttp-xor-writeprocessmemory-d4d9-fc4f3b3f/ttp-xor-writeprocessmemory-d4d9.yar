rule TTP_XOR_WriteProcessMemory_d4d9 {
  strings:
    $key_d4d9 = { 83 ab [2] b1 89 [2] b7 bc [2] 99 bc [2] a6 a0 }

  condition:
    any of them
}