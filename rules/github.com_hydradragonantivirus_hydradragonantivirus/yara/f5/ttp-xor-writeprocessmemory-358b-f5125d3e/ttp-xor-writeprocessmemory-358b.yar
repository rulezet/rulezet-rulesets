rule TTP_XOR_WriteProcessMemory_358b {
  strings:
    $key_358b = { 62 f9 [2] 50 db [2] 56 ee [2] 78 ee [2] 47 f2 }

  condition:
    any of them
}