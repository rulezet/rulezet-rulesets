rule TTP_XOR_WriteProcessMemory_a51c {
  strings:
    $key_a51c = { f2 6e [2] c0 4c [2] c6 79 [2] e8 79 [2] d7 65 }

  condition:
    any of them
}