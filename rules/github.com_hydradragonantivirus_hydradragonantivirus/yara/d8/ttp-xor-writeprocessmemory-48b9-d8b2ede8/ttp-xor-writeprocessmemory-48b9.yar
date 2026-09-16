rule TTP_XOR_WriteProcessMemory_48b9 {
  strings:
    $key_48b9 = { 1f cb [2] 2d e9 [2] 2b dc [2] 05 dc [2] 3a c0 }

  condition:
    any of them
}