rule TTP_XOR_WriteProcessMemory_b1b2 {
  strings:
    $key_b1b2 = { e6 c0 [2] d4 e2 [2] d2 d7 [2] fc d7 [2] c3 cb }

  condition:
    any of them
}