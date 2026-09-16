rule TTP_XOR_WriteProcessMemory_eb85 {
  strings:
    $key_eb85 = { bc f7 [2] 8e d5 [2] 88 e0 [2] a6 e0 [2] 99 fc }

  condition:
    any of them
}