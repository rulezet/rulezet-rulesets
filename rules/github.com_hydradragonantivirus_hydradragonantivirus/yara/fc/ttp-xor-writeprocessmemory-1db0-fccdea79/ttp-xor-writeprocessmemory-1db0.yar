rule TTP_XOR_WriteProcessMemory_1db0 {
  strings:
    $key_1db0 = { 4a c2 [2] 78 e0 [2] 7e d5 [2] 50 d5 [2] 6f c9 }

  condition:
    any of them
}