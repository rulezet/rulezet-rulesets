rule TTP_XOR_WriteProcessMemory_78b0 {
  strings:
    $key_78b0 = { 2f c2 [2] 1d e0 [2] 1b d5 [2] 35 d5 [2] 0a c9 }

  condition:
    any of them
}