rule TTP_XOR_WriteProcessMemory_5505 {
  strings:
    $key_5505 = { 02 77 [2] 30 55 [2] 36 60 [2] 18 60 [2] 27 7c }

  condition:
    any of them
}