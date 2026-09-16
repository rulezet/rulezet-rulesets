rule TTP_XOR_WriteProcessMemory_b34d {
  strings:
    $key_b34d = { e4 3f [2] d6 1d [2] d0 28 [2] fe 28 [2] c1 34 }

  condition:
    any of them
}