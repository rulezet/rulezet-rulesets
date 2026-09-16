rule TTP_XOR_WriteProcessMemory_0a7b {
  strings:
    $key_0a7b = { 5d 09 [2] 6f 2b [2] 69 1e [2] 47 1e [2] 78 02 }

  condition:
    any of them
}