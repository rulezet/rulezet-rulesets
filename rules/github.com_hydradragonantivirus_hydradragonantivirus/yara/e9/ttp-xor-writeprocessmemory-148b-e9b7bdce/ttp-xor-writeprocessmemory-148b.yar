rule TTP_XOR_WriteProcessMemory_148b {
  strings:
    $key_148b = { 43 f9 [2] 71 db [2] 77 ee [2] 59 ee [2] 66 f2 }

  condition:
    any of them
}