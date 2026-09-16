rule TTP_XOR_WriteProcessMemory_b362 {
  strings:
    $key_b362 = { e4 10 [2] d6 32 [2] d0 07 [2] fe 07 [2] c1 1b }

  condition:
    any of them
}