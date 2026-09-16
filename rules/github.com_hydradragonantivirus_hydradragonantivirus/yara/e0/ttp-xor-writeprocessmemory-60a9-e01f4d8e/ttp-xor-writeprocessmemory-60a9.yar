rule TTP_XOR_WriteProcessMemory_60a9 {
  strings:
    $key_60a9 = { 37 db [2] 05 f9 [2] 03 cc [2] 2d cc [2] 12 d0 }

  condition:
    any of them
}