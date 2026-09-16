rule TTP_XOR_WriteProcessMemory_b396 {
  strings:
    $key_b396 = { e4 e4 [2] d6 c6 [2] d0 f3 [2] fe f3 [2] c1 ef }

  condition:
    any of them
}