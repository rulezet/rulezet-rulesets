rule TTP_XOR_WriteProcessMemory_eb80 {
  strings:
    $key_eb80 = { bc f2 [2] 8e d0 [2] 88 e5 [2] a6 e5 [2] 99 f9 }

  condition:
    any of them
}