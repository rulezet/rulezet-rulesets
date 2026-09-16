rule TTP_XOR_WriteProcessMemory_4071 {
  strings:
    $key_4071 = { 17 03 [2] 25 21 [2] 23 14 [2] 0d 14 [2] 32 08 }

  condition:
    any of them
}