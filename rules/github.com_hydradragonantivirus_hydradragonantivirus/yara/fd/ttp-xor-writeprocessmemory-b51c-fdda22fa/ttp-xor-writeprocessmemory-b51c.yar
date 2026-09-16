rule TTP_XOR_WriteProcessMemory_b51c {
  strings:
    $key_b51c = { e2 6e [2] d0 4c [2] d6 79 [2] f8 79 [2] c7 65 }

  condition:
    any of them
}