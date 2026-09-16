rule TTP_XOR_WriteProcessMemory_b702 {
  strings:
    $key_b702 = { e0 70 [2] d2 52 [2] d4 67 [2] fa 67 [2] c5 7b }

  condition:
    any of them
}