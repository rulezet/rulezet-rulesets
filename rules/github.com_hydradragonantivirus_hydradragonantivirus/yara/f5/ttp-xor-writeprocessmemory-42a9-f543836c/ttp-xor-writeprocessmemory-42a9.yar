rule TTP_XOR_WriteProcessMemory_42a9 {
  strings:
    $key_42a9 = { 15 db [2] 27 f9 [2] 21 cc [2] 0f cc [2] 30 d0 }

  condition:
    any of them
}