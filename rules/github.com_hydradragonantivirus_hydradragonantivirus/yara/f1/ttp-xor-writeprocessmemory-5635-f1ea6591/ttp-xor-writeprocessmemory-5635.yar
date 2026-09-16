rule TTP_XOR_WriteProcessMemory_5635 {
  strings:
    $key_5635 = { 01 47 [2] 33 65 [2] 35 50 [2] 1b 50 [2] 24 4c }

  condition:
    any of them
}