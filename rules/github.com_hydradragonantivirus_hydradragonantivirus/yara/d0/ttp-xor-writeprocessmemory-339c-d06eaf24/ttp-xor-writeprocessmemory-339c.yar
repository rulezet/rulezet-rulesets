rule TTP_XOR_WriteProcessMemory_339c {
  strings:
    $key_339c = { 64 ee [2] 56 cc [2] 50 f9 [2] 7e f9 [2] 41 e5 }

  condition:
    any of them
}