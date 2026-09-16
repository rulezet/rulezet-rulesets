rule TTP_XOR_WriteProcessMemory_5ea9 {
  strings:
    $key_5ea9 = { 09 db [2] 3b f9 [2] 3d cc [2] 13 cc [2] 2c d0 }

  condition:
    any of them
}