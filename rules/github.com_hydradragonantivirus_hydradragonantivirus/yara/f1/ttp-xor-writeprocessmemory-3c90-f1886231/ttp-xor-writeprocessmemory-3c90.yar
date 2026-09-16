rule TTP_XOR_WriteProcessMemory_3c90 {
  strings:
    $key_3c90 = { 6b e2 [2] 59 c0 [2] 5f f5 [2] 71 f5 [2] 4e e9 }

  condition:
    any of them
}