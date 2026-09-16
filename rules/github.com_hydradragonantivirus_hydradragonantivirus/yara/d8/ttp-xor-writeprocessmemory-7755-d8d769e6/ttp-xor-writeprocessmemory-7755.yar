rule TTP_XOR_WriteProcessMemory_7755 {
  strings:
    $key_7755 = { 20 27 [2] 12 05 [2] 14 30 [2] 3a 30 [2] 05 2c }

  condition:
    any of them
}