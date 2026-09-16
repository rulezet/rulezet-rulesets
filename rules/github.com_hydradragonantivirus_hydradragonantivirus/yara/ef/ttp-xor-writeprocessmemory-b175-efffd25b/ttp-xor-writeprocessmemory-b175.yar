rule TTP_XOR_WriteProcessMemory_b175 {
  strings:
    $key_b175 = { e6 07 [2] d4 25 [2] d2 10 [2] fc 10 [2] c3 0c }

  condition:
    any of them
}