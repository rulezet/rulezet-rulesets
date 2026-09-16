rule TTP_XOR_WriteProcessMemory_e47b {
  strings:
    $key_e47b = { b3 09 [2] 81 2b [2] 87 1e [2] a9 1e [2] 96 02 }

  condition:
    any of them
}