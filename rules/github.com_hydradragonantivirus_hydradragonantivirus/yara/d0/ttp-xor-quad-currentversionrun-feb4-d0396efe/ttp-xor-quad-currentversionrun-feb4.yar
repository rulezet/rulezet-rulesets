rule TTP_XOR_QUAD_CurrentVersionRun_feb4 {
  strings:
    $key_feb4 = { ad db [2] 89 d5 [2] a2 f9 [2] 8c db [2] 98 c0 [2] 97 da [2] 89 c7 [2] 8b c6 [2] 90 c0 [2] 8c c7 [2] 90 e8 }

  condition:
    any of them
}