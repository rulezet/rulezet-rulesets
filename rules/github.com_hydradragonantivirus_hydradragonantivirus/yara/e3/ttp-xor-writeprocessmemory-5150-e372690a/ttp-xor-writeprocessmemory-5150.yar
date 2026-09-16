rule TTP_XOR_WriteProcessMemory_5150 {
  strings:
    $key_5150 = { 06 22 [2] 34 00 [2] 32 35 [2] 1c 35 [2] 23 29 }

  condition:
    any of them
}