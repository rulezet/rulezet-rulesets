rule TTP_XOR_WriteProcessMemory_6cbe {
  strings:
    $key_6cbe = { 3b cc [2] 09 ee [2] 0f db [2] 21 db [2] 1e c7 }

  condition:
    any of them
}