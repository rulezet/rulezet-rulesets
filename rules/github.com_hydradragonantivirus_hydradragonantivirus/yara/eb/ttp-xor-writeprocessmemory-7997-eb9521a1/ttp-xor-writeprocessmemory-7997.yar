rule TTP_XOR_WriteProcessMemory_7997 {
  strings:
    $key_7997 = { 2e e5 [2] 1c c7 [2] 1a f2 [2] 34 f2 [2] 0b ee }

  condition:
    any of them
}