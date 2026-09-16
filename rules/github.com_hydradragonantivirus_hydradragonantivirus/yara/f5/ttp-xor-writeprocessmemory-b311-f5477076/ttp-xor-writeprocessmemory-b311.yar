rule TTP_XOR_WriteProcessMemory_b311 {
  strings:
    $key_b311 = { e4 63 [2] d6 41 [2] d0 74 [2] fe 74 [2] c1 68 }

  condition:
    any of them
}