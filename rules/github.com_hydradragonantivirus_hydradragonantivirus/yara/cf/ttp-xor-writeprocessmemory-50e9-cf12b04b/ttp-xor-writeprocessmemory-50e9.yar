rule TTP_XOR_WriteProcessMemory_50e9 {
  strings:
    $key_50e9 = { 07 9b [2] 35 b9 [2] 33 8c [2] 1d 8c [2] 22 90 }

  condition:
    any of them
}