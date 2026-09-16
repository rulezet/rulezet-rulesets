rule TTP_XOR_WriteProcessMemory_2f50 {
  strings:
    $key_2f50 = { 78 22 [2] 4a 00 [2] 4c 35 [2] 62 35 [2] 5d 29 }

  condition:
    any of them
}