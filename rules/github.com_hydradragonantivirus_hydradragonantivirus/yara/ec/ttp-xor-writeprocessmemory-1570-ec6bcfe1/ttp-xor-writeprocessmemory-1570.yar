rule TTP_XOR_WriteProcessMemory_1570 {
  strings:
    $key_1570 = { 42 02 [2] 70 20 [2] 76 15 [2] 58 15 [2] 67 09 }

  condition:
    any of them
}