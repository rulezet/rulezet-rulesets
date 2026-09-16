rule TTP_XOR_WriteProcessMemory_2041 {
  strings:
    $key_2041 = { 77 33 [2] 45 11 [2] 43 24 [2] 6d 24 [2] 52 38 }

  condition:
    any of them
}