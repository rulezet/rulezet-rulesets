rule TTP_XOR_WriteProcessMemory_73f9 {
  strings:
    $key_73f9 = { 24 8b [2] 16 a9 [2] 10 9c [2] 3e 9c [2] 01 80 }

  condition:
    any of them
}