rule TTP_XOR_WriteProcessMemory_59a6 {
  strings:
    $key_59a6 = { 0e d4 [2] 3c f6 [2] 3a c3 [2] 14 c3 [2] 2b df }

  condition:
    any of them
}