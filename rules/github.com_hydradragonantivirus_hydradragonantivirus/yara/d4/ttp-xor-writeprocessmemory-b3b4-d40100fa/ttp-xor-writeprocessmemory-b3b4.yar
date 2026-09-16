rule TTP_XOR_WriteProcessMemory_b3b4 {
  strings:
    $key_b3b4 = { e4 c6 [2] d6 e4 [2] d0 d1 [2] fe d1 [2] c1 cd }

  condition:
    any of them
}