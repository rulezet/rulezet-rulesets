rule TTP_XOR_WriteProcessMemory_1d7b {
  strings:
    $key_1d7b = { 4a 09 [2] 78 2b [2] 7e 1e [2] 50 1e [2] 6f 02 }

  condition:
    any of them
}