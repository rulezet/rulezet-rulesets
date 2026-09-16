rule TTP_XOR_WriteProcessMemory_18a9 {
  strings:
    $key_18a9 = { 4f db [2] 7d f9 [2] 7b cc [2] 55 cc [2] 6a d0 }

  condition:
    any of them
}