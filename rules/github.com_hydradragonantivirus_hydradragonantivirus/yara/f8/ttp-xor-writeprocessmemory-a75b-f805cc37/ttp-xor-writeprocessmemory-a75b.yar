rule TTP_XOR_WriteProcessMemory_a75b {
  strings:
    $key_a75b = { f0 29 [2] c2 0b [2] c4 3e [2] ea 3e [2] d5 22 }

  condition:
    any of them
}