rule TTP_XOR_WriteProcessMemory_cab0 {
  strings:
    $key_cab0 = { 9d c2 [2] af e0 [2] a9 d5 [2] 87 d5 [2] b8 c9 }

  condition:
    any of them
}