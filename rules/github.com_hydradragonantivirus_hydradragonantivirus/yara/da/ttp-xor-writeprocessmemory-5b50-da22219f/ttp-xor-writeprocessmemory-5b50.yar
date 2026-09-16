rule TTP_XOR_WriteProcessMemory_5b50 {
  strings:
    $key_5b50 = { 0c 22 [2] 3e 00 [2] 38 35 [2] 16 35 [2] 29 29 }

  condition:
    any of them
}