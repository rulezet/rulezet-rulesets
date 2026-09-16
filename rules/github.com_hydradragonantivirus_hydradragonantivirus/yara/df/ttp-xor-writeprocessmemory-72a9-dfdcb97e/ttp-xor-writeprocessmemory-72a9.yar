rule TTP_XOR_WriteProcessMemory_72a9 {
  strings:
    $key_72a9 = { 25 db [2] 17 f9 [2] 11 cc [2] 3f cc [2] 00 d0 }

  condition:
    any of them
}