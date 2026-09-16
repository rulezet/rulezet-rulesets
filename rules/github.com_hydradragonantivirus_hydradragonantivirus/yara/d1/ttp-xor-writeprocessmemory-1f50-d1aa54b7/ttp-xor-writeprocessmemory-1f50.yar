rule TTP_XOR_WriteProcessMemory_1f50 {
  strings:
    $key_1f50 = { 48 22 [2] 7a 00 [2] 7c 35 [2] 52 35 [2] 6d 29 }

  condition:
    any of them
}