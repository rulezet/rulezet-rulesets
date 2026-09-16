rule TTP_XOR_WriteProcessMemory_1ea9 {
  strings:
    $key_1ea9 = { 49 db [2] 7b f9 [2] 7d cc [2] 53 cc [2] 6c d0 }

  condition:
    any of them
}