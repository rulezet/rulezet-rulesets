rule TTP_XOR_WriteProcessMemory_eb81 {
  strings:
    $key_eb81 = { bc f3 [2] 8e d1 [2] 88 e4 [2] a6 e4 [2] 99 f8 }

  condition:
    any of them
}