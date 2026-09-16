rule TTP_XOR_WriteProcessMemory_5009 {
  strings:
    $key_5009 = { 07 7b [2] 35 59 [2] 33 6c [2] 1d 6c [2] 22 70 }

  condition:
    any of them
}