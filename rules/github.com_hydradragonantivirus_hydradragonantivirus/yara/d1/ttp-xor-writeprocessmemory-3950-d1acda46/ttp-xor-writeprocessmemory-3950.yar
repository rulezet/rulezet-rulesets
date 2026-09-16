rule TTP_XOR_WriteProcessMemory_3950 {
  strings:
    $key_3950 = { 6e 22 [2] 5c 00 [2] 5a 35 [2] 74 35 [2] 4b 29 }

  condition:
    any of them
}