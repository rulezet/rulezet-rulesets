rule TTP_XOR_WriteProcessMemory_18b9 {
  strings:
    $key_18b9 = { 4f cb [2] 7d e9 [2] 7b dc [2] 55 dc [2] 6a c0 }

  condition:
    any of them
}