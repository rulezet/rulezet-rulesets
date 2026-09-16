rule TTP_XOR_WriteProcessMemory_7b49 {
  strings:
    $key_7b49 = { 2c 3b [2] 1e 19 [2] 18 2c [2] 36 2c [2] 09 30 }

  condition:
    any of them
}