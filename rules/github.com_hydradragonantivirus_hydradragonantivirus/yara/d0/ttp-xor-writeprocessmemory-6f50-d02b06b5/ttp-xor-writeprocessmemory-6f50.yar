rule TTP_XOR_WriteProcessMemory_6f50 {
  strings:
    $key_6f50 = { 38 22 [2] 0a 00 [2] 0c 35 [2] 22 35 [2] 1d 29 }

  condition:
    any of them
}