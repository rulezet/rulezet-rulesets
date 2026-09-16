rule TTP_XOR_WriteProcessMemory_2990 {
  strings:
    $key_2990 = { 7e e2 [2] 4c c0 [2] 4a f5 [2] 64 f5 [2] 5b e9 }

  condition:
    any of them
}