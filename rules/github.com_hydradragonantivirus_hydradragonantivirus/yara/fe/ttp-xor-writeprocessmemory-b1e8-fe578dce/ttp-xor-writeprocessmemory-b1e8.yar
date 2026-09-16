rule TTP_XOR_WriteProcessMemory_b1e8 {
  strings:
    $key_b1e8 = { e6 9a [2] d4 b8 [2] d2 8d [2] fc 8d [2] c3 91 }

  condition:
    any of them
}