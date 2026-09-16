rule TTP_XOR_WriteProcessMemory_5773 {
  strings:
    $key_5773 = { 00 01 [2] 32 23 [2] 34 16 [2] 1a 16 [2] 25 0a }

  condition:
    any of them
}