rule TTP_XOR_WriteProcessMemory_b31d {
  strings:
    $key_b31d = { e4 6f [2] d6 4d [2] d0 78 [2] fe 78 [2] c1 64 }

  condition:
    any of them
}