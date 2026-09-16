rule TTP_XOR_WriteProcessMemory_3590 {
  strings:
    $key_3590 = { 62 e2 [2] 50 c0 [2] 56 f5 [2] 78 f5 [2] 47 e9 }

  condition:
    any of them
}