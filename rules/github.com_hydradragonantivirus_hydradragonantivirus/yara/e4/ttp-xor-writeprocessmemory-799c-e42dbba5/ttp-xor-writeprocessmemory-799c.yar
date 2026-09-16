rule TTP_XOR_WriteProcessMemory_799c {
  strings:
    $key_799c = { 2e ee [2] 1c cc [2] 1a f9 [2] 34 f9 [2] 0b e5 }

  condition:
    any of them
}