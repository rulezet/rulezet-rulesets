rule TTP_XOR_WriteProcessMemory_2d7b {
  strings:
    $key_2d7b = { 7a 09 [2] 48 2b [2] 4e 1e [2] 60 1e [2] 5f 02 }

  condition:
    any of them
}