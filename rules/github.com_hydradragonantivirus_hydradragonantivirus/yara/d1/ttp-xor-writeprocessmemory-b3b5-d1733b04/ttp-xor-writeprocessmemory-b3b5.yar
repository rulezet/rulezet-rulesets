rule TTP_XOR_WriteProcessMemory_b3b5 {
  strings:
    $key_b3b5 = { e4 c7 [2] d6 e5 [2] d0 d0 [2] fe d0 [2] c1 cc }

  condition:
    any of them
}