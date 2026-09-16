rule TTP_XOR_WriteProcessMemory_7850 {
  strings:
    $key_7850 = { 2f 22 [2] 1d 00 [2] 1b 35 [2] 35 35 [2] 0a 29 }

  condition:
    any of them
}