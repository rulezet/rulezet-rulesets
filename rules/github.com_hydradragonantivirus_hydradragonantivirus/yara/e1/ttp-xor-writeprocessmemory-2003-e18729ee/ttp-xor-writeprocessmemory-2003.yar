rule TTP_XOR_WriteProcessMemory_2003 {
  strings:
    $key_2003 = { 77 71 [2] 45 53 [2] 43 66 [2] 6d 66 [2] 52 7a }

  condition:
    any of them
}