rule TTP_XOR_WriteProcessMemory_4cbe {
  strings:
    $key_4cbe = { 1b cc [2] 29 ee [2] 2f db [2] 01 db [2] 3e c7 }

  condition:
    any of them
}