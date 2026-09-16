rule TTP_XOR_WriteProcessMemory_3700 {
  strings:
    $key_3700 = { 60 72 [2] 52 50 [2] 54 65 [2] 7a 65 [2] 45 79 }

  condition:
    any of them
}