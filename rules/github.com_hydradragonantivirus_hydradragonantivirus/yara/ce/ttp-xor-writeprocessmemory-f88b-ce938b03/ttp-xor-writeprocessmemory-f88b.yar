rule TTP_XOR_WriteProcessMemory_f88b {
  strings:
    $key_f88b = { af f9 [2] 9d db [2] 9b ee [2] b5 ee [2] 8a f2 }

  condition:
    any of them
}