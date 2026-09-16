rule TTP_XOR_WriteProcessMemory_250b {
  strings:
    $key_250b = { 72 79 [2] 40 5b [2] 46 6e [2] 68 6e [2] 57 72 }

  condition:
    any of them
}