rule TTP_XOR_WriteProcessMemory_5fa9 {
  strings:
    $key_5fa9 = { 08 db [2] 3a f9 [2] 3c cc [2] 12 cc [2] 2d d0 }

  condition:
    any of them
}