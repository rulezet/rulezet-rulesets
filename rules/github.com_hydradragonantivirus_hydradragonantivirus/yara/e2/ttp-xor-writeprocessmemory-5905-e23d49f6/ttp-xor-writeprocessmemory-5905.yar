rule TTP_XOR_WriteProcessMemory_5905 {
  strings:
    $key_5905 = { 0e 77 [2] 3c 55 [2] 3a 60 [2] 14 60 [2] 2b 7c }

  condition:
    any of them
}