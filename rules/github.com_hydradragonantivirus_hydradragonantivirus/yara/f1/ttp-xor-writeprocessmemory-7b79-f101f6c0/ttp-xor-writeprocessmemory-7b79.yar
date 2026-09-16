rule TTP_XOR_WriteProcessMemory_7b79 {
  strings:
    $key_7b79 = { 2c 0b [2] 1e 29 [2] 18 1c [2] 36 1c [2] 09 00 }

  condition:
    any of them
}