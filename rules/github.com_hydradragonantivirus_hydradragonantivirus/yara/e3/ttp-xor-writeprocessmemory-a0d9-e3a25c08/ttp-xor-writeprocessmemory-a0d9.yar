rule TTP_XOR_WriteProcessMemory_a0d9 {
  strings:
    $key_a0d9 = { f7 ab [2] c5 89 [2] c3 bc [2] ed bc [2] d2 a0 }

  condition:
    any of them
}