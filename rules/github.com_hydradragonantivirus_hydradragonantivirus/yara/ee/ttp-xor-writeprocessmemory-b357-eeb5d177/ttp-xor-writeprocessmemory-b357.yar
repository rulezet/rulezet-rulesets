rule TTP_XOR_WriteProcessMemory_b357 {
  strings:
    $key_b357 = { e4 25 [2] d6 07 [2] d0 32 [2] fe 32 [2] c1 2e }

  condition:
    any of them
}