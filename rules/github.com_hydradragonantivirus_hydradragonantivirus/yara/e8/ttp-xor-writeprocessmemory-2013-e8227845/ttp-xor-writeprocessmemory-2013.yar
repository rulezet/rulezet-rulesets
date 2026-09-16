rule TTP_XOR_WriteProcessMemory_2013 {
  strings:
    $key_2013 = { 77 61 [2] 45 43 [2] 43 76 [2] 6d 76 [2] 52 6a }

  condition:
    any of them
}