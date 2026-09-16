rule TTP_XOR_WriteProcessMemory_1773 {
  strings:
    $key_1773 = { 40 01 [2] 72 23 [2] 74 16 [2] 5a 16 [2] 65 0a }

  condition:
    any of them
}