rule TTP_XOR_WriteProcessMemory_3a70 {
  strings:
    $key_3a70 = { 6d 02 [2] 5f 20 [2] 59 15 [2] 77 15 [2] 48 09 }

  condition:
    any of them
}