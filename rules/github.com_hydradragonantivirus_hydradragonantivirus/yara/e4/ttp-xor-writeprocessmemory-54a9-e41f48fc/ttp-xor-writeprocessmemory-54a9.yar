rule TTP_XOR_WriteProcessMemory_54a9 {
  strings:
    $key_54a9 = { 03 db [2] 31 f9 [2] 37 cc [2] 19 cc [2] 26 d0 }

  condition:
    any of them
}