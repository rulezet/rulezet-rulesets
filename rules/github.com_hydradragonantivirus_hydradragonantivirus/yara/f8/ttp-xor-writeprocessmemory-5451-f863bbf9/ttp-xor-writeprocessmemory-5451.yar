rule TTP_XOR_WriteProcessMemory_5451 {
  strings:
    $key_5451 = { 03 23 [2] 31 01 [2] 37 34 [2] 19 34 [2] 26 28 }

  condition:
    any of them
}