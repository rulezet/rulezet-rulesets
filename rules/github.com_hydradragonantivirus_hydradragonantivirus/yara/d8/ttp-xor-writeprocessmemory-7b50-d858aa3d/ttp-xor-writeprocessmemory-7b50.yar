rule TTP_XOR_WriteProcessMemory_7b50 {
  strings:
    $key_7b50 = { 2c 22 [2] 1e 00 [2] 18 35 [2] 36 35 [2] 09 29 }

  condition:
    any of them
}