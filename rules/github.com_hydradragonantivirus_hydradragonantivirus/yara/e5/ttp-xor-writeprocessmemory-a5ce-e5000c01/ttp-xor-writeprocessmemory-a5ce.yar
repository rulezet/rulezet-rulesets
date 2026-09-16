rule TTP_XOR_WriteProcessMemory_a5ce {
  strings:
    $key_a5ce = { f2 bc [2] c0 9e [2] c6 ab [2] e8 ab [2] d7 b7 }

  condition:
    any of them
}