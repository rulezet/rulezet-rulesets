rule TTP_XOR_WriteProcessMemory_4007 {
  strings:
    $key_4007 = { 17 75 [2] 25 57 [2] 23 62 [2] 0d 62 [2] 32 7e }

  condition:
    any of them
}