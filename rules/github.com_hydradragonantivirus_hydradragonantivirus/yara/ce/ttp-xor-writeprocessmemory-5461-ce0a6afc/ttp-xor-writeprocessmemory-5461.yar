rule TTP_XOR_WriteProcessMemory_5461 {
  strings:
    $key_5461 = { 03 13 [2] 31 31 [2] 37 04 [2] 19 04 [2] 26 18 }

  condition:
    any of them
}