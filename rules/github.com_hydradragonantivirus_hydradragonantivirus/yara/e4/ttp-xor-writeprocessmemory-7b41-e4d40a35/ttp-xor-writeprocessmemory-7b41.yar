rule TTP_XOR_WriteProcessMemory_7b41 {
  strings:
    $key_7b41 = { 2c 33 [2] 1e 11 [2] 18 24 [2] 36 24 [2] 09 38 }

  condition:
    any of them
}