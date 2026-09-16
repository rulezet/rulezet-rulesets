rule TTP_XOR_WriteProcessMemory_44b9 {
  strings:
    $key_44b9 = { 13 cb [2] 21 e9 [2] 27 dc [2] 09 dc [2] 36 c0 }

  condition:
    any of them
}