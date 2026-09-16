rule TTP_XOR_WriteProcessMemory_7672 {
  strings:
    $key_7672 = { 21 00 [2] 13 22 [2] 15 17 [2] 3b 17 [2] 04 0b }

  condition:
    any of them
}