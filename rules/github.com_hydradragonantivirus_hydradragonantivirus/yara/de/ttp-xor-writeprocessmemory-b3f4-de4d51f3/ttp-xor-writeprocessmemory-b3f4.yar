rule TTP_XOR_WriteProcessMemory_b3f4 {
  strings:
    $key_b3f4 = { e4 86 [2] d6 a4 [2] d0 91 [2] fe 91 [2] c1 8d }

  condition:
    any of them
}