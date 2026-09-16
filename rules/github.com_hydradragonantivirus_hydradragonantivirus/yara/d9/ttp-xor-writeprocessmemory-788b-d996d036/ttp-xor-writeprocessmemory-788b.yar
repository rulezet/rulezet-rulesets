rule TTP_XOR_WriteProcessMemory_788b {
  strings:
    $key_788b = { 2f f9 [2] 1d db [2] 1b ee [2] 35 ee [2] 0a f2 }

  condition:
    any of them
}