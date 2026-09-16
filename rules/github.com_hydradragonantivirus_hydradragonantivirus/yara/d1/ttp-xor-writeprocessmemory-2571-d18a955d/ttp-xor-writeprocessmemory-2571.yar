rule TTP_XOR_WriteProcessMemory_2571 {
  strings:
    $key_2571 = { 72 03 [2] 40 21 [2] 46 14 [2] 68 14 [2] 57 08 }

  condition:
    any of them
}