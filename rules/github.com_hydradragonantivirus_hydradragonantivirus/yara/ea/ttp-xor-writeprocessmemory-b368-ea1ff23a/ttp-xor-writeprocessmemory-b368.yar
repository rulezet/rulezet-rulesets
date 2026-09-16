rule TTP_XOR_WriteProcessMemory_b368 {
  strings:
    $key_b368 = { e4 1a [2] d6 38 [2] d0 0d [2] fe 0d [2] c1 11 }

  condition:
    any of them
}