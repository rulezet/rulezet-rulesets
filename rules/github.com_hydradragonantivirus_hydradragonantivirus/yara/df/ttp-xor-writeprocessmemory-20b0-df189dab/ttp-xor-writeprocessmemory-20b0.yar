rule TTP_XOR_WriteProcessMemory_20b0 {
  strings:
    $key_20b0 = { 77 c2 [2] 45 e0 [2] 43 d5 [2] 6d d5 [2] 52 c9 }

  condition:
    any of them
}