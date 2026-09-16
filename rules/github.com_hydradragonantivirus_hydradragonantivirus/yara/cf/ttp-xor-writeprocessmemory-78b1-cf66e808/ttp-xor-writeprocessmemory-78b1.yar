rule TTP_XOR_WriteProcessMemory_78b1 {
  strings:
    $key_78b1 = { 2f c3 [2] 1d e1 [2] 1b d4 [2] 35 d4 [2] 0a c8 }

  condition:
    any of them
}