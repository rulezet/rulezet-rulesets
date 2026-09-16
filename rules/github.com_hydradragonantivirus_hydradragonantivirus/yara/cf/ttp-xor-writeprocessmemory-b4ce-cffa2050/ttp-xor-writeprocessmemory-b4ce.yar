rule TTP_XOR_WriteProcessMemory_b4ce {
  strings:
    $key_b4ce = { e3 bc [2] d1 9e [2] d7 ab [2] f9 ab [2] c6 b7 }

  condition:
    any of them
}