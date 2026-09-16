rule TTP_XOR_WriteProcessMemory_67a9 {
  strings:
    $key_67a9 = { 30 db [2] 02 f9 [2] 04 cc [2] 2a cc [2] 15 d0 }

  condition:
    any of them
}