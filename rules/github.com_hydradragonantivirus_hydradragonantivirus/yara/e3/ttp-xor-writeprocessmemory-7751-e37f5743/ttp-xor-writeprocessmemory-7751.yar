rule TTP_XOR_WriteProcessMemory_7751 {
  strings:
    $key_7751 = { 20 23 [2] 12 01 [2] 14 34 [2] 3a 34 [2] 05 28 }

  condition:
    any of them
}