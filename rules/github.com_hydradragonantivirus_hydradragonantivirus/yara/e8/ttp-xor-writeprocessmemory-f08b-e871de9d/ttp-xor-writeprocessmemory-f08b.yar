rule TTP_XOR_WriteProcessMemory_f08b {
  strings:
    $key_f08b = { a7 f9 [2] 95 db [2] 93 ee [2] bd ee [2] 82 f2 }

  condition:
    any of them
}