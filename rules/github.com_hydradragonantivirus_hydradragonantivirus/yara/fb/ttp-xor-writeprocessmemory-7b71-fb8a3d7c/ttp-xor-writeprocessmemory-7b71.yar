rule TTP_XOR_WriteProcessMemory_7b71 {
  strings:
    $key_7b71 = { 2c 03 [2] 1e 21 [2] 18 14 [2] 36 14 [2] 09 08 }

  condition:
    any of them
}