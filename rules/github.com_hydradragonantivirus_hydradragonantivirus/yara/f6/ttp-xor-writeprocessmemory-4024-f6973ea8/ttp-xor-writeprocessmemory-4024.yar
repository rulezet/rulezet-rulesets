rule TTP_XOR_WriteProcessMemory_4024 {
  strings:
    $key_4024 = { 17 56 [2] 25 74 [2] 23 41 [2] 0d 41 [2] 32 5d }

  condition:
    any of them
}