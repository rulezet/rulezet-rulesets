rule TTP_XOR_QUAD_CurrentVersionRun_0097 {
  strings:
    $key_0097 = { 53 f8 [2] 77 f6 [2] 5c da [2] 72 f8 [2] 66 e3 [2] 69 f9 [2] 77 e4 [2] 75 e5 [2] 6e e3 [2] 72 e4 [2] 6e cb }

  condition:
    any of them
}