rule TTP_XOR_WriteProcessMemory_4432 {
  strings:
    $key_4432 = { 13 40 [2] 21 62 [2] 27 57 [2] 09 57 [2] 36 4b }

  condition:
    any of them
}