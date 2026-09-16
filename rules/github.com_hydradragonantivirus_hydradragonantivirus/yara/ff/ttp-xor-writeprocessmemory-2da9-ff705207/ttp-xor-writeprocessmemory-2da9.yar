rule TTP_XOR_WriteProcessMemory_2da9 {
  strings:
    $key_2da9 = { 7a db [2] 48 f9 [2] 4e cc [2] 60 cc [2] 5f d0 }

  condition:
    any of them
}