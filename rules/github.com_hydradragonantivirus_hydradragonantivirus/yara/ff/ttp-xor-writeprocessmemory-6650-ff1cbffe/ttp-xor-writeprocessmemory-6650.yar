rule TTP_XOR_WriteProcessMemory_6650 {
  strings:
    $key_6650 = { 31 22 [2] 03 00 [2] 05 35 [2] 2b 35 [2] 14 29 }

  condition:
    any of them
}