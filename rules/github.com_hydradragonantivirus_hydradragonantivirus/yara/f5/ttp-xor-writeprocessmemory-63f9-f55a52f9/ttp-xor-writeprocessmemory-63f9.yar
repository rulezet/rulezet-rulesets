rule TTP_XOR_WriteProcessMemory_63f9 {
  strings:
    $key_63f9 = { 34 8b [2] 06 a9 [2] 00 9c [2] 2e 9c [2] 11 80 }

  condition:
    any of them
}