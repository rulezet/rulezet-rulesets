rule TTP_XOR_WriteProcessMemory_45a9 {
  strings:
    $key_45a9 = { 12 db [2] 20 f9 [2] 26 cc [2] 08 cc [2] 37 d0 }

  condition:
    any of them
}