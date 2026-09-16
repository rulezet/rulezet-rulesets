rule TTP_XOR_WriteProcessMemory_5e8b {
  strings:
    $key_5e8b = { 09 f9 [2] 3b db [2] 3d ee [2] 13 ee [2] 2c f2 }

  condition:
    any of them
}