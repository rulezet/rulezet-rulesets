rule TTP_XOR_WriteProcessMemory_399c {
  strings:
    $key_399c = { 6e ee [2] 5c cc [2] 5a f9 [2] 74 f9 [2] 4b e5 }

  condition:
    any of them
}