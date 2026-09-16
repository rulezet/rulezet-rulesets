rule TTP_XOR_WriteProcessMemory_20a2 {
  strings:
    $key_20a2 = { 77 d0 [2] 45 f2 [2] 43 c7 [2] 6d c7 [2] 52 db }

  condition:
    any of them
}