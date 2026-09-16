rule TTP_XOR_WriteProcessMemory_40f7 {
  strings:
    $key_40f7 = { 17 85 [2] 25 a7 [2] 23 92 [2] 0d 92 [2] 32 8e }

  condition:
    any of them
}