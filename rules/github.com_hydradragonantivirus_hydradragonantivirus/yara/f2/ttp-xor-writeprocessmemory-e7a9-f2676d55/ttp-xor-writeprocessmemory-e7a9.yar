rule TTP_XOR_WriteProcessMemory_e7a9 {
  strings:
    $key_e7a9 = { b0 db [2] 82 f9 [2] 84 cc [2] aa cc [2] 95 d0 }

  condition:
    any of them
}