rule TTP_XOR_WriteProcessMemory_be8b {
  strings:
    $key_be8b = { e9 f9 [2] db db [2] dd ee [2] f3 ee [2] cc f2 }

  condition:
    any of them
}