rule TTP_XOR_WriteProcessMemory_b1a8 {
  strings:
    $key_b1a8 = { e6 da [2] d4 f8 [2] d2 cd [2] fc cd [2] c3 d1 }

  condition:
    any of them
}