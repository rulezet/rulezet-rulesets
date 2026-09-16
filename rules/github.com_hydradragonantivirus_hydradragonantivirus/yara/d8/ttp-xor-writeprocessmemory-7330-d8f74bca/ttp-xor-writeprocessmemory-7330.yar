rule TTP_XOR_WriteProcessMemory_7330 {
  strings:
    $key_7330 = { 24 42 [2] 16 60 [2] 10 55 [2] 3e 55 [2] 01 49 }

  condition:
    any of them
}