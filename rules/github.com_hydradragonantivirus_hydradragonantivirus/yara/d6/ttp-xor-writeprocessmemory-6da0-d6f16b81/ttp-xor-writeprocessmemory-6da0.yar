rule TTP_XOR_WriteProcessMemory_6da0 {
  strings:
    $key_6da0 = { 3a d2 [2] 08 f0 [2] 0e c5 [2] 20 c5 [2] 1f d9 }

  condition:
    any of them
}