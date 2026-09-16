rule TTP_XOR_WriteProcessMemory_4407 {
  strings:
    $key_4407 = { 13 75 [2] 21 57 [2] 27 62 [2] 09 62 [2] 36 7e }

  condition:
    any of them
}