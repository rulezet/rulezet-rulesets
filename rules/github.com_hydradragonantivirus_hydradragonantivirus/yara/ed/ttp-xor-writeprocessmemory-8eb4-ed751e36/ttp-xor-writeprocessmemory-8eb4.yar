rule TTP_XOR_WriteProcessMemory_8eb4 {
  strings:
    $key_8eb4 = { d9 c6 [2] eb e4 [2] ed d1 [2] c3 d1 [2] fc cd }

  condition:
    any of them
}