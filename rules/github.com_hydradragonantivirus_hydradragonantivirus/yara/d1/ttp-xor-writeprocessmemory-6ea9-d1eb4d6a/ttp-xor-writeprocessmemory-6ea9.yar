rule TTP_XOR_WriteProcessMemory_6ea9 {
  strings:
    $key_6ea9 = { 39 db [2] 0b f9 [2] 0d cc [2] 23 cc [2] 1c d0 }

  condition:
    any of them
}