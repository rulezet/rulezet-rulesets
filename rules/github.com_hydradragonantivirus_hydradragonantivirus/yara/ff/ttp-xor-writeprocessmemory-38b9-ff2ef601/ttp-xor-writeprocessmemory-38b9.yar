rule TTP_XOR_WriteProcessMemory_38b9 {
  strings:
    $key_38b9 = { 6f cb [2] 5d e9 [2] 5b dc [2] 75 dc [2] 4a c0 }

  condition:
    any of them
}