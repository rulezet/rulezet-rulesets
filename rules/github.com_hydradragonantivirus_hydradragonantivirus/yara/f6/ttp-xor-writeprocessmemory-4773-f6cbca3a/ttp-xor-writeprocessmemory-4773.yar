rule TTP_XOR_WriteProcessMemory_4773 {
  strings:
    $key_4773 = { 10 01 [2] 22 23 [2] 24 16 [2] 0a 16 [2] 35 0a }

  condition:
    any of them
}