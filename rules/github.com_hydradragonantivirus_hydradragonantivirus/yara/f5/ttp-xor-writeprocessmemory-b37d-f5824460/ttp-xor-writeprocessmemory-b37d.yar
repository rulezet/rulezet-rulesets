rule TTP_XOR_WriteProcessMemory_b37d {
  strings:
    $key_b37d = { e4 0f [2] d6 2d [2] d0 18 [2] fe 18 [2] c1 04 }

  condition:
    any of them
}