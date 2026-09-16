rule TTP_XOR_WriteProcessMemory_b4f5 {
  strings:
    $key_b4f5 = { e3 87 [2] d1 a5 [2] d7 90 [2] f9 90 [2] c6 8c }

  condition:
    any of them
}