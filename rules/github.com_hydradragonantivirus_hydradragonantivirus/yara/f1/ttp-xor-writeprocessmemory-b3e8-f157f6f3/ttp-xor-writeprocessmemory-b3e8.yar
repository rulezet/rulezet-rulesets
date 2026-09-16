rule TTP_XOR_WriteProcessMemory_b3e8 {
  strings:
    $key_b3e8 = { e4 9a [2] d6 b8 [2] d0 8d [2] fe 8d [2] c1 91 }

  condition:
    any of them
}