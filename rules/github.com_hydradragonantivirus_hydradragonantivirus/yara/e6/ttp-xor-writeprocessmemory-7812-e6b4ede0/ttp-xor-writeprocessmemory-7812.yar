rule TTP_XOR_WriteProcessMemory_7812 {
  strings:
    $key_7812 = { 2f 60 [2] 1d 42 [2] 1b 77 [2] 35 77 [2] 0a 6b }

  condition:
    any of them
}