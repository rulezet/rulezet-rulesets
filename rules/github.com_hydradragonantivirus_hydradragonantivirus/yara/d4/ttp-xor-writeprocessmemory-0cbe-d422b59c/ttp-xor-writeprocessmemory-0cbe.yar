rule TTP_XOR_WriteProcessMemory_0cbe {
  strings:
    $key_0cbe = { 5b cc [2] 69 ee [2] 6f db [2] 41 db [2] 7e c7 }

  condition:
    any of them
}