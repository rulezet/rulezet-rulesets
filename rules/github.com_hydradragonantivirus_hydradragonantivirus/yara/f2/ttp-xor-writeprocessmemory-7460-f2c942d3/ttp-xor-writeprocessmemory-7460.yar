rule TTP_XOR_WriteProcessMemory_7460 {
  strings:
    $key_7460 = { 23 12 [2] 11 30 [2] 17 05 [2] 39 05 [2] 06 19 }

  condition:
    any of them
}