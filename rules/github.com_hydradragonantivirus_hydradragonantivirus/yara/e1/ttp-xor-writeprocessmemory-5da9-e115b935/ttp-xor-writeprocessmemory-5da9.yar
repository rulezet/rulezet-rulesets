rule TTP_XOR_WriteProcessMemory_5da9 {
  strings:
    $key_5da9 = { 0a db [2] 38 f9 [2] 3e cc [2] 10 cc [2] 2f d0 }

  condition:
    any of them
}