rule TTP_XOR_WriteProcessMemory_499c {
  strings:
    $key_499c = { 1e ee [2] 2c cc [2] 2a f9 [2] 04 f9 [2] 3b e5 }

  condition:
    any of them
}