rule TTP_XOR_WriteProcessMemory_ea98 {
  strings:
    $key_ea98 = { bd ea [2] 8f c8 [2] 89 fd [2] a7 fd [2] 98 e1 }

  condition:
    any of them
}