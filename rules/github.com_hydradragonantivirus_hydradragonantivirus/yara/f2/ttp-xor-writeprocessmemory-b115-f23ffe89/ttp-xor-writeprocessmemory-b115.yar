rule TTP_XOR_WriteProcessMemory_b115 {
  strings:
    $key_b115 = { e6 67 [2] d4 45 [2] d2 70 [2] fc 70 [2] c3 6c }

  condition:
    any of them
}