rule TTP_XOR_WriteProcessMemory_0da9 {
  strings:
    $key_0da9 = { 5a db [2] 68 f9 [2] 6e cc [2] 40 cc [2] 7f d0 }

  condition:
    any of them
}