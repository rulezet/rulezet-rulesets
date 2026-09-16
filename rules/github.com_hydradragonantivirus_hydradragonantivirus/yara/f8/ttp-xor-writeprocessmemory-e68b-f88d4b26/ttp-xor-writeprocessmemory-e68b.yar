rule TTP_XOR_WriteProcessMemory_e68b {
  strings:
    $key_e68b = { b1 f9 [2] 83 db [2] 85 ee [2] ab ee [2] 94 f2 }

  condition:
    any of them
}