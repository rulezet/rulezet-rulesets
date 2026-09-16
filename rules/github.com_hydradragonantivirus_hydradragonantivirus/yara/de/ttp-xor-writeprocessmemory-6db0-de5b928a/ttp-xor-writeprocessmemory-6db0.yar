rule TTP_XOR_WriteProcessMemory_6db0 {
  strings:
    $key_6db0 = { 3a c2 [2] 08 e0 [2] 0e d5 [2] 20 d5 [2] 1f c9 }

  condition:
    any of them
}