rule TTP_XOR_WriteProcessMemory_2991 {
  strings:
    $key_2991 = { 7e e3 [2] 4c c1 [2] 4a f4 [2] 64 f4 [2] 5b e8 }

  condition:
    any of them
}