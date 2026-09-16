rule TTP_XOR_WriteProcessMemory_4679 {
  strings:
    $key_4679 = { 11 0b [2] 23 29 [2] 25 1c [2] 0b 1c [2] 34 00 }

  condition:
    any of them
}