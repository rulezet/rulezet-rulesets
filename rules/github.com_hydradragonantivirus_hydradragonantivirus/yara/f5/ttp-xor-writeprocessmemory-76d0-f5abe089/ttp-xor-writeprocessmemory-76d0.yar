rule TTP_XOR_WriteProcessMemory_76d0 {
  strings:
    $key_76d0 = { 21 a2 [2] 13 80 [2] 15 b5 [2] 3b b5 [2] 04 a9 }

  condition:
    any of them
}