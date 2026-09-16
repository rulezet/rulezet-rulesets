rule TTP_XOR_WriteProcessMemory_12d0 {
  strings:
    $key_12d0 = { 45 a2 [2] 77 80 [2] 71 b5 [2] 5f b5 [2] 60 a9 }

  condition:
    any of them
}