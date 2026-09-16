rule TTP_XOR_WriteProcessMemory_2ea9 {
  strings:
    $key_2ea9 = { 79 db [2] 4b f9 [2] 4d cc [2] 63 cc [2] 5c d0 }

  condition:
    any of them
}