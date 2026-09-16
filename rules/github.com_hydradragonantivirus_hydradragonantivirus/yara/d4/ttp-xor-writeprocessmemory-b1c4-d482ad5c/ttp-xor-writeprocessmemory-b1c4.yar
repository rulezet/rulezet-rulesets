rule TTP_XOR_WriteProcessMemory_b1c4 {
  strings:
    $key_b1c4 = { e6 b6 [2] d4 94 [2] d2 a1 [2] fc a1 [2] c3 bd }

  condition:
    any of them
}