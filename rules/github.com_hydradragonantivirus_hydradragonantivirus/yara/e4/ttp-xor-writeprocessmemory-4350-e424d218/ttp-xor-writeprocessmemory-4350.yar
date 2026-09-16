rule TTP_XOR_WriteProcessMemory_4350 {
  strings:
    $key_4350 = { 14 22 [2] 26 00 [2] 20 35 [2] 0e 35 [2] 31 29 }

  condition:
    any of them
}