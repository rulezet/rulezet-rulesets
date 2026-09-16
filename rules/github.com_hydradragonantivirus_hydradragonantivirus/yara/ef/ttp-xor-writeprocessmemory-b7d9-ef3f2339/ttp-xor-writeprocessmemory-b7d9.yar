rule TTP_XOR_WriteProcessMemory_b7d9 {
  strings:
    $key_b7d9 = { e0 ab [2] d2 89 [2] d4 bc [2] fa bc [2] c5 a0 }

  condition:
    any of them
}