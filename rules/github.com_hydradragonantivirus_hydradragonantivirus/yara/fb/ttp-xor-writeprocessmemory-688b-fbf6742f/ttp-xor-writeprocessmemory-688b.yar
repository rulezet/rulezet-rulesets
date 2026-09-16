rule TTP_XOR_WriteProcessMemory_688b {
  strings:
    $key_688b = { 3f f9 [2] 0d db [2] 0b ee [2] 25 ee [2] 1a f2 }

  condition:
    any of them
}