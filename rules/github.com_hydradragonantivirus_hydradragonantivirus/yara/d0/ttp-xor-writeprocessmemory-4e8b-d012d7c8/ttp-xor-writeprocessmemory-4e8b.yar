rule TTP_XOR_WriteProcessMemory_4e8b {
  strings:
    $key_4e8b = { 19 f9 [2] 2b db [2] 2d ee [2] 03 ee [2] 3c f2 }

  condition:
    any of them
}