rule TTP_XOR_WriteProcessMemory_7145 {
  strings:
    $key_7145 = { 26 37 [2] 14 15 [2] 12 20 [2] 3c 20 [2] 03 3c }

  condition:
    any of them
}