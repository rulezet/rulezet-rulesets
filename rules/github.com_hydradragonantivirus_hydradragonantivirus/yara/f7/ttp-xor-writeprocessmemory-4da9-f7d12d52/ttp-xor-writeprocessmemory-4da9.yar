rule TTP_XOR_WriteProcessMemory_4da9 {
  strings:
    $key_4da9 = { 1a db [2] 28 f9 [2] 2e cc [2] 00 cc [2] 3f d0 }

  condition:
    any of them
}