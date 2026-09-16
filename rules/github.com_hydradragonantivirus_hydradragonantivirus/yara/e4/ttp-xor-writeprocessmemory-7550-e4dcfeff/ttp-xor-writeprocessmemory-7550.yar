rule TTP_XOR_WriteProcessMemory_7550 {
  strings:
    $key_7550 = { 22 22 [2] 10 00 [2] 16 35 [2] 38 35 [2] 07 29 }

  condition:
    any of them
}