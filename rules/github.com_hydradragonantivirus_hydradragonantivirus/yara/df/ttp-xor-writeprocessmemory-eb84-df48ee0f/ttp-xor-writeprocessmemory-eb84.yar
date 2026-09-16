rule TTP_XOR_WriteProcessMemory_eb84 {
  strings:
    $key_eb84 = { bc f6 [2] 8e d4 [2] 88 e1 [2] a6 e1 [2] 99 fd }

  condition:
    any of them
}