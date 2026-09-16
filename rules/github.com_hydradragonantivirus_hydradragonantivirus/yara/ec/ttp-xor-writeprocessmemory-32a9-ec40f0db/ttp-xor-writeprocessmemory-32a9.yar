rule TTP_XOR_WriteProcessMemory_32a9 {
  strings:
    $key_32a9 = { 65 db [2] 57 f9 [2] 51 cc [2] 7f cc [2] 40 d0 }

  condition:
    any of them
}