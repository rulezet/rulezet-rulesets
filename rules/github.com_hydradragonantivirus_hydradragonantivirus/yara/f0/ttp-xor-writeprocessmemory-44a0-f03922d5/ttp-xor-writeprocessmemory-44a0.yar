rule TTP_XOR_WriteProcessMemory_44a0 {
  strings:
    $key_44a0 = { 13 d2 [2] 21 f0 [2] 27 c5 [2] 09 c5 [2] 36 d9 }

  condition:
    any of them
}