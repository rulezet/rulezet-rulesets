rule TTP_XOR_WriteProcessMemory_4352 {
  strings:
    $key_4352 = { 14 20 [2] 26 02 [2] 20 37 [2] 0e 37 [2] 31 2b }

  condition:
    any of them
}