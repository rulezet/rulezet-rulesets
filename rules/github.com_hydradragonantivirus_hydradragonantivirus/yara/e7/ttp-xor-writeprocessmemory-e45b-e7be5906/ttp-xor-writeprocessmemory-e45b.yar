rule TTP_XOR_WriteProcessMemory_e45b {
  strings:
    $key_e45b = { b3 29 [2] 81 0b [2] 87 3e [2] a9 3e [2] 96 22 }

  condition:
    any of them
}