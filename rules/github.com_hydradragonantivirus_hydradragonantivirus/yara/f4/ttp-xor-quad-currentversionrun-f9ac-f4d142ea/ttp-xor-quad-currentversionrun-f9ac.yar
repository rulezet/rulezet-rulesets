rule TTP_XOR_QUAD_CurrentVersionRun_f9ac {
  strings:
    $key_f9ac = { aa c3 [2] 8e cd [2] a5 e1 [2] 8b c3 [2] 9f d8 [2] 90 c2 [2] 8e df [2] 8c de [2] 97 d8 [2] 8b df [2] 97 f0 }

  condition:
    any of them
}