rule TTP_XOR_WriteProcessMemory_5707 {
  strings:
    $key_5707 = { 00 75 [2] 32 57 [2] 34 62 [2] 1a 62 [2] 25 7e }

  condition:
    any of them
}