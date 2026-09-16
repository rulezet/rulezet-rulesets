rule TTP_XOR_WriteProcessMemory_49f9 {
  strings:
    $key_49f9 = { 1e 8b [2] 2c a9 [2] 2a 9c [2] 04 9c [2] 3b 80 }

  condition:
    any of them
}