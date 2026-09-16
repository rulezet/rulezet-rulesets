rule TTP_XOR_WriteProcessMemory_2514 {
  strings:
    $key_2514 = { 72 66 [2] 40 44 [2] 46 71 [2] 68 71 [2] 57 6d }

  condition:
    any of them
}