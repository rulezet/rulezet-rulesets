rule TTP_XOR_WriteProcessMemory_13a9 {
  strings:
    $key_13a9 = { 44 db [2] 76 f9 [2] 70 cc [2] 5e cc [2] 61 d0 }

  condition:
    any of them
}