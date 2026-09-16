rule TTP_XOR_WriteProcessMemory_2f7b {
  strings:
    $key_2f7b = { 78 09 [2] 4a 2b [2] 4c 1e [2] 62 1e [2] 5d 02 }

  condition:
    any of them
}