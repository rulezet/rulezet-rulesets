rule TTP_XOR_WriteProcessMemory_b33d {
  strings:
    $key_b33d = { e4 4f [2] d6 6d [2] d0 58 [2] fe 58 [2] c1 44 }

  condition:
    any of them
}