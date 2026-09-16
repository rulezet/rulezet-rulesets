rule TTP_XOR_WriteProcessMemory_11b0 {
  strings:
    $key_11b0 = { 46 c2 [2] 74 e0 [2] 72 d5 [2] 5c d5 [2] 63 c9 }

  condition:
    any of them
}