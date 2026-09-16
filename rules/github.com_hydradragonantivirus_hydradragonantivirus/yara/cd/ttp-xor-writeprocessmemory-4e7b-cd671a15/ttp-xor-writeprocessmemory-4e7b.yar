rule TTP_XOR_WriteProcessMemory_4e7b {
  strings:
    $key_4e7b = { 19 09 [2] 2b 2b [2] 2d 1e [2] 03 1e [2] 3c 02 }

  condition:
    any of them
}