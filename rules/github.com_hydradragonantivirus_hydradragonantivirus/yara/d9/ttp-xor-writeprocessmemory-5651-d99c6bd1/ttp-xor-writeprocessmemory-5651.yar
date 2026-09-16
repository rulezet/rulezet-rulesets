rule TTP_XOR_WriteProcessMemory_5651 {
  strings:
    $key_5651 = { 01 23 [2] 33 01 [2] 35 34 [2] 1b 34 [2] 24 28 }

  condition:
    any of them
}