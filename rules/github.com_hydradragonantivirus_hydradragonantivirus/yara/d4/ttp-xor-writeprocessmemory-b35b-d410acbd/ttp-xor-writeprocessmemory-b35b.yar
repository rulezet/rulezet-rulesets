rule TTP_XOR_WriteProcessMemory_b35b {
  strings:
    $key_b35b = { e4 29 [2] d6 0b [2] d0 3e [2] fe 3e [2] c1 22 }

  condition:
    any of them
}