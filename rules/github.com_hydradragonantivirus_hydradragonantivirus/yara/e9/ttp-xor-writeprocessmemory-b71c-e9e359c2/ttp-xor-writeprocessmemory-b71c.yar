rule TTP_XOR_WriteProcessMemory_b71c {
  strings:
    $key_b71c = { e0 6e [2] d2 4c [2] d4 79 [2] fa 79 [2] c5 65 }

  condition:
    any of them
}