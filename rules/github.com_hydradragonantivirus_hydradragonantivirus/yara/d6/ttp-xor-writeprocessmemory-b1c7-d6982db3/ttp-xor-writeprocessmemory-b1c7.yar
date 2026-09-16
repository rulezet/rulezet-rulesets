rule TTP_XOR_WriteProcessMemory_b1c7 {
  strings:
    $key_b1c7 = { e6 b5 [2] d4 97 [2] d2 a2 [2] fc a2 [2] c3 be }

  condition:
    any of them
}