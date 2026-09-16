rule TTP_XOR_WriteProcessMemory_058b {
  strings:
    $key_058b = { 52 f9 [2] 60 db [2] 66 ee [2] 48 ee [2] 77 f2 }

  condition:
    any of them
}