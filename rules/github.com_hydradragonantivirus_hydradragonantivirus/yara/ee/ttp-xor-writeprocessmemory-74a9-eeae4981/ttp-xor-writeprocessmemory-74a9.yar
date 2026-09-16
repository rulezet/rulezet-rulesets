rule TTP_XOR_WriteProcessMemory_74a9 {
  strings:
    $key_74a9 = { 23 db [2] 11 f9 [2] 17 cc [2] 39 cc [2] 06 d0 }

  condition:
    any of them
}