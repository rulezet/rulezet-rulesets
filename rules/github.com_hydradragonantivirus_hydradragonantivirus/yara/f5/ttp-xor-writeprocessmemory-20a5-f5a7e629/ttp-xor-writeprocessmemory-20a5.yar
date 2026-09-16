rule TTP_XOR_WriteProcessMemory_20a5 {
  strings:
    $key_20a5 = { 77 d7 [2] 45 f5 [2] 43 c0 [2] 6d c0 [2] 52 dc }

  condition:
    any of them
}