rule TTP_XOR_WriteProcessMemory_fca9 {
  strings:
    $key_fca9 = { ab db [2] 99 f9 [2] 9f cc [2] b1 cc [2] 8e d0 }

  condition:
    any of them
}