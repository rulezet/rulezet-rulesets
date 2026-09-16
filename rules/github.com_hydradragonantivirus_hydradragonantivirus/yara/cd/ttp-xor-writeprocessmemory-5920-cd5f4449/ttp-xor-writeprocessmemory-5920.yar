rule TTP_XOR_WriteProcessMemory_5920 {
  strings:
    $key_5920 = { 0e 52 [2] 3c 70 [2] 3a 45 [2] 14 45 [2] 2b 59 }

  condition:
    any of them
}