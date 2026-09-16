rule TTP_XOR_WriteProcessMemory_3ea9 {
  strings:
    $key_3ea9 = { 69 db [2] 5b f9 [2] 5d cc [2] 73 cc [2] 4c d0 }

  condition:
    any of them
}