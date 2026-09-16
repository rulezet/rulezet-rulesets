rule TTP_XOR_WriteProcessMemory_7e8b {
  strings:
    $key_7e8b = { 29 f9 [2] 1b db [2] 1d ee [2] 33 ee [2] 0c f2 }

  condition:
    any of them
}