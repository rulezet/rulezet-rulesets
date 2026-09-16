rule TTP_XOR_WriteProcessMemory_7741 {
  strings:
    $key_7741 = { 20 33 [2] 12 11 [2] 14 24 [2] 3a 24 [2] 05 38 }

  condition:
    any of them
}