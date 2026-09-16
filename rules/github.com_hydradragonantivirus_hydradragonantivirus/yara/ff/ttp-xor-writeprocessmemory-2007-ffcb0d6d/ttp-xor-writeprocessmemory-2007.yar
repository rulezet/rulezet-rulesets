rule TTP_XOR_WriteProcessMemory_2007 {
  strings:
    $key_2007 = { 77 75 [2] 45 57 [2] 43 62 [2] 6d 62 [2] 52 7e }

  condition:
    any of them
}