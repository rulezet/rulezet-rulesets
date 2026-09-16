rule TTP_XOR_WriteProcessMemory_efb0 {
  strings:
    $key_efb0 = { b8 c2 [2] 8a e0 [2] 8c d5 [2] a2 d5 [2] 9d c9 }

  condition:
    any of them
}