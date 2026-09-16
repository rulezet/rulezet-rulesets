rule TTP_XOR_WriteProcessMemory_cfa0 {
  strings:
    $key_cfa0 = { 98 d2 [2] aa f0 [2] ac c5 [2] 82 c5 [2] bd d9 }

  condition:
    any of them
}