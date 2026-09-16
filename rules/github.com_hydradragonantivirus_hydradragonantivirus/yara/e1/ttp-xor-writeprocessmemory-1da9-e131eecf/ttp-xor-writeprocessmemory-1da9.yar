rule TTP_XOR_WriteProcessMemory_1da9 {
  strings:
    $key_1da9 = { 4a db [2] 78 f9 [2] 7e cc [2] 50 cc [2] 6f d0 }

  condition:
    any of them
}