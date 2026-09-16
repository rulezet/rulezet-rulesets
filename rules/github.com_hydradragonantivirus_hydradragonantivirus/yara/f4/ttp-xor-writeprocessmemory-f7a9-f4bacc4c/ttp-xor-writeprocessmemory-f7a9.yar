rule TTP_XOR_WriteProcessMemory_f7a9 {
  strings:
    $key_f7a9 = { a0 db [2] 92 f9 [2] 94 cc [2] ba cc [2] 85 d0 }

  condition:
    any of them
}