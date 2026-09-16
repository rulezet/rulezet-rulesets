rule TTP_XOR_WriteProcessMemory_a25b {
  strings:
    $key_a25b = { f5 29 [2] c7 0b [2] c1 3e [2] ef 3e [2] d0 22 }

  condition:
    any of them
}