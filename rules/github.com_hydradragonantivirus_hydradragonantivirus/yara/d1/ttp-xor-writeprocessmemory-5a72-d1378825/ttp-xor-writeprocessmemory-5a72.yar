rule TTP_XOR_WriteProcessMemory_5a72 {
  strings:
    $key_5a72 = { 0d 00 [2] 3f 22 [2] 39 17 [2] 17 17 [2] 28 0b }

  condition:
    any of them
}