rule TTP_XOR_WriteProcessMemory_7770 {
  strings:
    $key_7770 = { 20 02 [2] 12 20 [2] 14 15 [2] 3a 15 [2] 05 09 }

  condition:
    any of them
}