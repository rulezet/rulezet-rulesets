rule TTP_XOR_WriteProcessMemory_0772 {
  strings:
    $key_0772 = { 50 00 [2] 62 22 [2] 64 17 [2] 4a 17 [2] 75 0b }

  condition:
    any of them
}