rule TTP_XOR_WriteProcessMemory_579c {
  strings:
    $key_579c = { 00 ee [2] 32 cc [2] 34 f9 [2] 1a f9 [2] 25 e5 }

  condition:
    any of them
}