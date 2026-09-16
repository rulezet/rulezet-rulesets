rule TTP_XOR_WriteProcessMemory_49b2 {
  strings:
    $key_49b2 = { 1e c0 [2] 2c e2 [2] 2a d7 [2] 04 d7 [2] 3b cb }

  condition:
    any of them
}