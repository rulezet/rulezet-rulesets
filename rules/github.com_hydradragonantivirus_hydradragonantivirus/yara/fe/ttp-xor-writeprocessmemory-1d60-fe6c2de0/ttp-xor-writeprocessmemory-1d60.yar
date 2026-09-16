rule TTP_XOR_WriteProcessMemory_1d60 {
  strings:
    $key_1d60 = { 4a 12 [2] 78 30 [2] 7e 05 [2] 50 05 [2] 6f 19 }

  condition:
    any of them
}