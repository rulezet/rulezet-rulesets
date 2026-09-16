rule TTP_XOR_WriteProcessMemory_f5a9 {
  strings:
    $key_f5a9 = { a2 db [2] 90 f9 [2] 96 cc [2] b8 cc [2] 87 d0 }

  condition:
    any of them
}