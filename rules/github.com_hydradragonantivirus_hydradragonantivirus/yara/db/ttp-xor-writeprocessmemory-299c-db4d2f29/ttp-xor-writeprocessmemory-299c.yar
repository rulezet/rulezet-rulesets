rule TTP_XOR_WriteProcessMemory_299c {
  strings:
    $key_299c = { 7e ee [2] 4c cc [2] 4a f9 [2] 64 f9 [2] 5b e5 }

  condition:
    any of them
}