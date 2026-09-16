rule TTP_XOR_WriteProcessMemory_2002 {
  strings:
    $key_2002 = { 77 70 [2] 45 52 [2] 43 67 [2] 6d 67 [2] 52 7b }

  condition:
    any of them
}