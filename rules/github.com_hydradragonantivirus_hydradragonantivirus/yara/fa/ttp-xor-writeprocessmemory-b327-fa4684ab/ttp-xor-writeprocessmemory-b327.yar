rule TTP_XOR_WriteProcessMemory_b327 {
  strings:
    $key_b327 = { e4 55 [2] d6 77 [2] d0 42 [2] fe 42 [2] c1 5e }

  condition:
    any of them
}