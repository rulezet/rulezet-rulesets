rule TTP_XOR_WriteProcessMemory_7360 {
  strings:
    $key_7360 = { 24 12 [2] 16 30 [2] 10 05 [2] 3e 05 [2] 01 19 }

  condition:
    any of them
}