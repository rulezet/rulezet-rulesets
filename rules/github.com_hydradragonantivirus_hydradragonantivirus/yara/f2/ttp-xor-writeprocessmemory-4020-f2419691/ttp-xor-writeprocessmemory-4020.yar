rule TTP_XOR_WriteProcessMemory_4020 {
  strings:
    $key_4020 = { 17 52 [2] 25 70 [2] 23 45 [2] 0d 45 [2] 32 59 }

  condition:
    any of them
}