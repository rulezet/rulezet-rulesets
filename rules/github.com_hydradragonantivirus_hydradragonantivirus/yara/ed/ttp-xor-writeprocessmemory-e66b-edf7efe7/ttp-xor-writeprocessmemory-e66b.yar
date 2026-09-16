rule TTP_XOR_WriteProcessMemory_e66b {
  strings:
    $key_e66b = { b1 19 [2] 83 3b [2] 85 0e [2] ab 0e [2] 94 12 }

  condition:
    any of them
}