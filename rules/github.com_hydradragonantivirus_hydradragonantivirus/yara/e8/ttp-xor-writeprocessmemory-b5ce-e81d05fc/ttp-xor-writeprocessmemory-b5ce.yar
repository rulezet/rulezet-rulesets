rule TTP_XOR_WriteProcessMemory_b5ce {
  strings:
    $key_b5ce = { e2 bc [2] d0 9e [2] d6 ab [2] f8 ab [2] c7 b7 }

  condition:
    any of them
}