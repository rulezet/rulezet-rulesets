rule TTP_XOR_WriteProcessMemory_b315 {
  strings:
    $key_b315 = { e4 67 [2] d6 45 [2] d0 70 [2] fe 70 [2] c1 6c }

  condition:
    any of them
}