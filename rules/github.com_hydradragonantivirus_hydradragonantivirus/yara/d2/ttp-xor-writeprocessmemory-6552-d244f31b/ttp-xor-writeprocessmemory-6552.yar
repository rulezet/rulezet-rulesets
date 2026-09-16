rule TTP_XOR_WriteProcessMemory_6552 {
  strings:
    $key_6552 = { 32 20 [2] 00 02 [2] 06 37 [2] 28 37 [2] 17 2b }

  condition:
    any of them
}