rule TTP_XOR_WriteProcessMemory_1fa9 {
  strings:
    $key_1fa9 = { 48 db [2] 7a f9 [2] 7c cc [2] 52 cc [2] 6d d0 }

  condition:
    any of them
}