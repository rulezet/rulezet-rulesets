rule TTP_XOR_WriteProcessMemory_cfa9 {
  strings:
    $key_cfa9 = { 98 db [2] aa f9 [2] ac cc [2] 82 cc [2] bd d0 }

  condition:
    any of them
}