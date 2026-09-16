rule TTP_XOR_WriteProcessMemory_5630 {
  strings:
    $key_5630 = { 01 42 [2] 33 60 [2] 35 55 [2] 1b 55 [2] 24 49 }

  condition:
    any of them
}