rule TTP_XOR_WriteProcessMemory_5561 {
  strings:
    $key_5561 = { 02 13 [2] 30 31 [2] 36 04 [2] 18 04 [2] 27 18 }

  condition:
    any of them
}