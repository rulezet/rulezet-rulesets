rule TTP_XOR_WriteProcessMemory_2000 {
  strings:
    $key_2000 = { 77 72 [2] 45 50 [2] 43 65 [2] 6d 65 [2] 52 79 }

  condition:
    any of them
}