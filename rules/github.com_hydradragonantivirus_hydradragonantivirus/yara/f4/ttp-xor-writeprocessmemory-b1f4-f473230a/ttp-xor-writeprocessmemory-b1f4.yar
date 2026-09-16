rule TTP_XOR_WriteProcessMemory_b1f4 {
  strings:
    $key_b1f4 = { e6 86 [2] d4 a4 [2] d2 91 [2] fc 91 [2] c3 8d }

  condition:
    any of them
}