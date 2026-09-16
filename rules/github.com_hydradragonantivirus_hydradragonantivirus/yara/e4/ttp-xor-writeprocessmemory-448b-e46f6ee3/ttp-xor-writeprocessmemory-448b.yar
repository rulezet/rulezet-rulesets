rule TTP_XOR_WriteProcessMemory_448b {
  strings:
    $key_448b = { 13 f9 [2] 21 db [2] 27 ee [2] 09 ee [2] 36 f2 }

  condition:
    any of them
}