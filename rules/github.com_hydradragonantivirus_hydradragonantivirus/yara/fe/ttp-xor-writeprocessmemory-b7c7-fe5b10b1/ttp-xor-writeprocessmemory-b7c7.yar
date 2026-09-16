rule TTP_XOR_WriteProcessMemory_b7c7 {
  strings:
    $key_b7c7 = { e0 b5 [2] d2 97 [2] d4 a2 [2] fa a2 [2] c5 be }

  condition:
    any of them
}