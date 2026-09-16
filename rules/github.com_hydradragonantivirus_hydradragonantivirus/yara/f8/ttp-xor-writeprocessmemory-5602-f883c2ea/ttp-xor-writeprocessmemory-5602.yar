rule TTP_XOR_WriteProcessMemory_5602 {
  strings:
    $key_5602 = { 01 70 [2] 33 52 [2] 35 67 [2] 1b 67 [2] 24 7b }

  condition:
    any of them
}