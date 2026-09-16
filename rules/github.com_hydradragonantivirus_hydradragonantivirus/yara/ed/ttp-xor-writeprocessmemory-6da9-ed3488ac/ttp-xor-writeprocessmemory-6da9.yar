rule TTP_XOR_WriteProcessMemory_6da9 {
  strings:
    $key_6da9 = { 3a db [2] 08 f9 [2] 0e cc [2] 20 cc [2] 1f d0 }

  condition:
    any of them
}