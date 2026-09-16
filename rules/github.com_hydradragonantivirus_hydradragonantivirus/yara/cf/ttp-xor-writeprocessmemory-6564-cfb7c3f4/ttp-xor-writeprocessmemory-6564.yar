rule TTP_XOR_WriteProcessMemory_6564 {
  strings:
    $key_6564 = { 32 16 [2] 00 34 [2] 06 01 [2] 28 01 [2] 17 1d }

  condition:
    any of them
}