rule TTP_XOR_WriteProcessMemory_76f0 {
  strings:
    $key_76f0 = { 21 82 [2] 13 a0 [2] 15 95 [2] 3b 95 [2] 04 89 }

  condition:
    any of them
}