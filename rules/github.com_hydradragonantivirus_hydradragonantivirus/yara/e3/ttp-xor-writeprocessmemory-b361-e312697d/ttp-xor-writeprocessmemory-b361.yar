rule TTP_XOR_WriteProcessMemory_b361 {
  strings:
    $key_b361 = { e4 13 [2] d6 31 [2] d0 04 [2] fe 04 [2] c1 18 }

  condition:
    any of them
}