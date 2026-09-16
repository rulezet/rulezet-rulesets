rule TTP_XOR_WriteProcessMemory_b2f2 {
  strings:
    $key_b2f2 = { e5 80 [2] d7 a2 [2] d1 97 [2] ff 97 [2] c0 8b }

  condition:
    any of them
}