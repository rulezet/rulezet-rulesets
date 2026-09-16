rule TTP_XOR_WriteProcessMemory_7300 {
  strings:
    $key_7300 = { 24 72 [2] 16 50 [2] 10 65 [2] 3e 65 [2] 01 79 }

  condition:
    any of them
}