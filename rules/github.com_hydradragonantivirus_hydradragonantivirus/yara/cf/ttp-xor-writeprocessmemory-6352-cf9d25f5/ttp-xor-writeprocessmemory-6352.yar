rule TTP_XOR_WriteProcessMemory_6352 {
  strings:
    $key_6352 = { 34 20 [2] 06 02 [2] 00 37 [2] 2e 37 [2] 11 2b }

  condition:
    any of them
}