rule TTP_XOR_WriteProcessMemory_d8b1 {
  strings:
    $key_d8b1 = { 8f c3 [2] bd e1 [2] bb d4 [2] 95 d4 [2] aa c8 }

  condition:
    any of them
}