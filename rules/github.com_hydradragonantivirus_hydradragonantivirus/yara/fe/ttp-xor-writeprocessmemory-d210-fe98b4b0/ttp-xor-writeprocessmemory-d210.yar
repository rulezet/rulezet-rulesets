rule TTP_XOR_WriteProcessMemory_d210 {
  strings:
    $key_d210 = { 85 62 [2] b7 40 [2] b1 75 [2] 9f 75 [2] a0 69 }

  condition:
    any of them
}