rule TTP_XOR_WriteProcessMemory_2cbe {
  strings:
    $key_2cbe = { 7b cc [2] 49 ee [2] 4f db [2] 61 db [2] 5e c7 }

  condition:
    any of them
}