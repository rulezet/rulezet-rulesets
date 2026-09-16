rule TTP_XOR_WriteProcessMemory_b125 {
  strings:
    $key_b125 = { e6 57 [2] d4 75 [2] d2 40 [2] fc 40 [2] c3 5c }

  condition:
    any of them
}