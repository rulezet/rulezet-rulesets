rule TTP_XOR_WriteProcessMemory_4371 {
  strings:
    $key_4371 = { 14 03 [2] 26 21 [2] 20 14 [2] 0e 14 [2] 31 08 }

  condition:
    any of them
}