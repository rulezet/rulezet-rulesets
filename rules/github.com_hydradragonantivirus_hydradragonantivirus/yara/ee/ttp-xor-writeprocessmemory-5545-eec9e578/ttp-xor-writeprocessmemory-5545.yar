rule TTP_XOR_WriteProcessMemory_5545 {
  strings:
    $key_5545 = { 02 37 [2] 30 15 [2] 36 20 [2] 18 20 [2] 27 3c }

  condition:
    any of them
}