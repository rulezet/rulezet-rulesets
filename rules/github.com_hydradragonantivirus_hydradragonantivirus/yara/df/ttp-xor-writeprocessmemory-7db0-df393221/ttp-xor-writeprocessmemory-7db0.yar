rule TTP_XOR_WriteProcessMemory_7db0 {
  strings:
    $key_7db0 = { 2a c2 [2] 18 e0 [2] 1e d5 [2] 30 d5 [2] 0f c9 }

  condition:
    any of them
}