rule TTP_XOR_WriteProcessMemory_7e50 {
  strings:
    $key_7e50 = { 29 22 [2] 1b 00 [2] 1d 35 [2] 33 35 [2] 0c 29 }

  condition:
    any of them
}