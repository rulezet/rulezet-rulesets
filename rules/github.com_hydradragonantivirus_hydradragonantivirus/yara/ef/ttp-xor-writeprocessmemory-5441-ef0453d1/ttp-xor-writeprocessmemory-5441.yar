rule TTP_XOR_WriteProcessMemory_5441 {
  strings:
    $key_5441 = { 03 33 [2] 31 11 [2] 37 24 [2] 19 24 [2] 26 38 }

  condition:
    any of them
}