rule TTP_XOR_WriteProcessMemory_b1d0 {
  strings:
    $key_b1d0 = { e6 a2 [2] d4 80 [2] d2 b5 [2] fc b5 [2] c3 a9 }

  condition:
    any of them
}