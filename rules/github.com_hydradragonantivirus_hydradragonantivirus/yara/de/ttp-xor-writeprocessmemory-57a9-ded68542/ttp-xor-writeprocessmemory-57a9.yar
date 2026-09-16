rule TTP_XOR_WriteProcessMemory_57a9 {
  strings:
    $key_57a9 = { 00 db [2] 32 f9 [2] 34 cc [2] 1a cc [2] 25 d0 }

  condition:
    any of them
}