rule TTP_XOR_WriteProcessMemory_b130 {
  strings:
    $key_b130 = { e6 42 [2] d4 60 [2] d2 55 [2] fc 55 [2] c3 49 }

  condition:
    any of them
}