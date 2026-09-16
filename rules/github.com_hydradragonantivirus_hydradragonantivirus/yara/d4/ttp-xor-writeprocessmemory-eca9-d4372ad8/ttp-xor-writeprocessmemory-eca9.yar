rule TTP_XOR_WriteProcessMemory_eca9 {
  strings:
    $key_eca9 = { bb db [2] 89 f9 [2] 8f cc [2] a1 cc [2] 9e d0 }

  condition:
    any of them
}