rule TTP_XOR_WriteProcessMemory_25a9 {
  strings:
    $key_25a9 = { 72 db [2] 40 f9 [2] 46 cc [2] 68 cc [2] 57 d0 }

  condition:
    any of them
}