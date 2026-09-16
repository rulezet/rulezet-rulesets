rule TTP_XOR_WriteProcessMemory_7615 {
  strings:
    $key_7615 = { 21 67 [2] 13 45 [2] 15 70 [2] 3b 70 [2] 04 6c }

  condition:
    any of them
}