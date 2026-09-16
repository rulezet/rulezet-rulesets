rule TTP_XOR_WriteProcessMemory_e46b {
  strings:
    $key_e46b = { b3 19 [2] 81 3b [2] 87 0e [2] a9 0e [2] 96 12 }

  condition:
    any of them
}