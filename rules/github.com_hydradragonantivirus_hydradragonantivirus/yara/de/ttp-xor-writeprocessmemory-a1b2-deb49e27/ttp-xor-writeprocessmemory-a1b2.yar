rule TTP_XOR_WriteProcessMemory_a1b2 {
  strings:
    $key_a1b2 = { f6 c0 [2] c4 e2 [2] c2 d7 [2] ec d7 [2] d3 cb }

  condition:
    any of them
}