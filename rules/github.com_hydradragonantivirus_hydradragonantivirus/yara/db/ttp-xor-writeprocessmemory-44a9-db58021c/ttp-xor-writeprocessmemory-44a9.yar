rule TTP_XOR_WriteProcessMemory_44a9 {
  strings:
    $key_44a9 = { 13 db [2] 21 f9 [2] 27 cc [2] 09 cc [2] 36 d0 }

  condition:
    any of them
}