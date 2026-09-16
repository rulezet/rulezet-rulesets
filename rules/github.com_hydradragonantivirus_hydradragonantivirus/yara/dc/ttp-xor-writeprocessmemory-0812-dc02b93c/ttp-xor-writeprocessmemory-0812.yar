rule TTP_XOR_WriteProcessMemory_0812 {
  strings:
    $key_0812 = { 5f 60 [2] 6d 42 [2] 6b 77 [2] 45 77 [2] 7a 6b }

  condition:
    any of them
}