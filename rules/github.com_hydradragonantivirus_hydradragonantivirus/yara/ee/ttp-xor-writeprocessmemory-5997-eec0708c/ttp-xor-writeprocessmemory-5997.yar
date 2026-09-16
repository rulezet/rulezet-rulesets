rule TTP_XOR_WriteProcessMemory_5997 {
  strings:
    $key_5997 = { 0e e5 [2] 3c c7 [2] 3a f2 [2] 14 f2 [2] 2b ee }

  condition:
    any of them
}