rule TTP_XOR_WriteProcessMemory_1812 {
  strings:
    $key_1812 = { 4f 60 [2] 7d 42 [2] 7b 77 [2] 55 77 [2] 6a 6b }

  condition:
    any of them
}