rule TTP_XOR_WriteProcessMemory_c99b {
  strings:
    $key_c99b = { 9e e9 [2] ac cb [2] aa fe [2] 84 fe [2] bb e2 }

  condition:
    any of them
}