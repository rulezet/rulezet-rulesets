rule TTP_XOR_WriteProcessMemory_079c {
  strings:
    $key_079c = { 50 ee [2] 62 cc [2] 64 f9 [2] 4a f9 [2] 75 e5 }

  condition:
    any of them
}