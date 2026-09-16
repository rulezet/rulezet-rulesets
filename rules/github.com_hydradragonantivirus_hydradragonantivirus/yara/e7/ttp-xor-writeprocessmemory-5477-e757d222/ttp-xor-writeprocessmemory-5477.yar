rule TTP_XOR_WriteProcessMemory_5477 {
  strings:
    $key_5477 = { 03 05 [2] 31 27 [2] 37 12 [2] 19 12 [2] 26 0e }

  condition:
    any of them
}