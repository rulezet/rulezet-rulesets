rule TTP_XOR_WriteProcessMemory_ea8c {
  strings:
    $key_ea8c = { bd fe [2] 8f dc [2] 89 e9 [2] a7 e9 [2] 98 f5 }

  condition:
    any of them
}