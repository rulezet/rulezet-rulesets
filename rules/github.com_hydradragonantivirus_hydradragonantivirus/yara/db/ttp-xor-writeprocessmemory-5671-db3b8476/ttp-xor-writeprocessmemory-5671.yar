rule TTP_XOR_WriteProcessMemory_5671 {
  strings:
    $key_5671 = { 01 03 [2] 33 21 [2] 35 14 [2] 1b 14 [2] 24 08 }

  condition:
    any of them
}