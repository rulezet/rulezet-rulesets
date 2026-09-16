rule TTP_XOR_WriteProcessMemory_3a92 {
  strings:
    $key_3a92 = { 6d e0 [2] 5f c2 [2] 59 f7 [2] 77 f7 [2] 48 eb }

  condition:
    any of them
}