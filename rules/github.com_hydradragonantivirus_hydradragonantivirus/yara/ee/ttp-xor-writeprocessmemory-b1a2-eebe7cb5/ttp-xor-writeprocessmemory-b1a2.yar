rule TTP_XOR_WriteProcessMemory_b1a2 {
  strings:
    $key_b1a2 = { e6 d0 [2] d4 f2 [2] d2 c7 [2] fc c7 [2] c3 db }

  condition:
    any of them
}