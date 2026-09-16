rule TTP_XOR_WriteProcessMemory_dda9 {
  strings:
    $key_dda9 = { 8a db [2] b8 f9 [2] be cc [2] 90 cc [2] af d0 }

  condition:
    any of them
}