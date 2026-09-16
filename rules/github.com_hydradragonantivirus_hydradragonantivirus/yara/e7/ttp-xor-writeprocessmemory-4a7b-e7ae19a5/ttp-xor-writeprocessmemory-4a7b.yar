rule TTP_XOR_WriteProcessMemory_4a7b {
  strings:
    $key_4a7b = { 1d 09 [2] 2f 2b [2] 29 1e [2] 07 1e [2] 38 02 }

  condition:
    any of them
}