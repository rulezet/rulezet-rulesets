rule TTP_XOR_WriteProcessMemory_7765 {
  strings:
    $key_7765 = { 20 17 [2] 12 35 [2] 14 00 [2] 3a 00 [2] 05 1c }

  condition:
    any of them
}