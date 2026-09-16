rule TTP_XOR_WriteProcessMemory_257b {
  strings:
    $key_257b = { 72 09 [2] 40 2b [2] 46 1e [2] 68 1e [2] 57 02 }

  condition:
    any of them
}