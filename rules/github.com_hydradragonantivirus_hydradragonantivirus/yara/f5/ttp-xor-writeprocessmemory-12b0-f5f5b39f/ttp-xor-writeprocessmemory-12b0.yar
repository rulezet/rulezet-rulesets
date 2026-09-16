rule TTP_XOR_WriteProcessMemory_12b0 {
  strings:
    $key_12b0 = { 45 c2 [2] 77 e0 [2] 71 d5 [2] 5f d5 [2] 60 c9 }

  condition:
    any of them
}