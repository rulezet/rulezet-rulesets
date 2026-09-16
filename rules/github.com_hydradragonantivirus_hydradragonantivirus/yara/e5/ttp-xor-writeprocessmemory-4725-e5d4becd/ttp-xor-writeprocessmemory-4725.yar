rule TTP_XOR_WriteProcessMemory_4725 {
  strings:
    $key_4725 = { 10 57 [2] 22 75 [2] 24 40 [2] 0a 40 [2] 35 5c }

  condition:
    any of them
}