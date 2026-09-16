rule TTP_XOR_WriteProcessMemory_eca0 {
  strings:
    $key_eca0 = { bb d2 [2] 89 f0 [2] 8f c5 [2] a1 c5 [2] 9e d9 }

  condition:
    any of them
}