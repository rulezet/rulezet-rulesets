rule TTP_XOR_WriteProcessMemory_0950 {
  strings:
    $key_0950 = { 5e 22 [2] 6c 00 [2] 6a 35 [2] 44 35 [2] 7b 29 }

  condition:
    any of them
}