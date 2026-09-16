rule TTP_XOR_WriteProcessMemory_3350 {
  strings:
    $key_3350 = { 64 22 [2] 56 00 [2] 50 35 [2] 7e 35 [2] 41 29 }

  condition:
    any of them
}