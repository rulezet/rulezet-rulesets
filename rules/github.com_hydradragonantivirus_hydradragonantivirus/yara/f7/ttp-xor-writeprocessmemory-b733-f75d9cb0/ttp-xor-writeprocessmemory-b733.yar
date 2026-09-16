rule TTP_XOR_WriteProcessMemory_b733 {
  strings:
    $key_b733 = { e0 41 [2] d2 63 [2] d4 56 [2] fa 56 [2] c5 4a }

  condition:
    any of them
}