rule TTP_XOR_WriteProcessMemory_1912 {
  strings:
    $key_1912 = { 4e 60 [2] 7c 42 [2] 7a 77 [2] 54 77 [2] 6b 6b }

  condition:
    any of them
}