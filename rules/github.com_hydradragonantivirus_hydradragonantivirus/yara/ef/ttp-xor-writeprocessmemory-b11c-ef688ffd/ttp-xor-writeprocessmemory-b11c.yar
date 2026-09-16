rule TTP_XOR_WriteProcessMemory_b11c {
  strings:
    $key_b11c = { e6 6e [2] d4 4c [2] d2 79 [2] fc 79 [2] c3 65 }

  condition:
    any of them
}