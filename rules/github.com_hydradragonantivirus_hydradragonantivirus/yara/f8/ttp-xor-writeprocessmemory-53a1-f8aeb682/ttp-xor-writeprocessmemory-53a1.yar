rule TTP_XOR_WriteProcessMemory_53a1 {
  strings:
    $key_53a1 = { 04 d3 [2] 36 f1 [2] 30 c4 [2] 1e c4 [2] 21 d8 }

  condition:
    any of them
}