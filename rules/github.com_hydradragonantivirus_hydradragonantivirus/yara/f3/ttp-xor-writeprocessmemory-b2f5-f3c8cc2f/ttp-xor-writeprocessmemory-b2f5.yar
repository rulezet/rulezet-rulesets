rule TTP_XOR_WriteProcessMemory_b2f5 {
  strings:
    $key_b2f5 = { e5 87 [2] d7 a5 [2] d1 90 [2] ff 90 [2] c0 8c }

  condition:
    any of them
}