rule TTP_XOR_WriteProcessMemory_b112 {
  strings:
    $key_b112 = { e6 60 [2] d4 42 [2] d2 77 [2] fc 77 [2] c3 6b }

  condition:
    any of them
}