rule TTP_XOR_WriteProcessMemory_187b {
  strings:
    $key_187b = { 4f 09 [2] 7d 2b [2] 7b 1e [2] 55 1e [2] 6a 02 }

  condition:
    any of them
}