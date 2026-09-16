rule TTP_XOR_WriteProcessMemory_e67b {
  strings:
    $key_e67b = { b1 09 [2] 83 2b [2] 85 1e [2] ab 1e [2] 94 02 }

  condition:
    any of them
}