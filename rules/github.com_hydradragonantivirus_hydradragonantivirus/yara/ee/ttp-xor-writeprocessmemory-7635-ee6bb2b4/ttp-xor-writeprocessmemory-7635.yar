rule TTP_XOR_WriteProcessMemory_7635 {
  strings:
    $key_7635 = { 21 47 [2] 13 65 [2] 15 50 [2] 3b 50 [2] 04 4c }

  condition:
    any of them
}