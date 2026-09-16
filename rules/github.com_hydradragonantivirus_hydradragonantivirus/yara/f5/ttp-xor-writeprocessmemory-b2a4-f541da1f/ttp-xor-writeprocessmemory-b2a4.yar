rule TTP_XOR_WriteProcessMemory_b2a4 {
  strings:
    $key_b2a4 = { e5 d6 [2] d7 f4 [2] d1 c1 [2] ff c1 [2] c0 dd }

  condition:
    any of them
}