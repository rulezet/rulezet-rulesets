rule TTP_XOR_QUAD_CurrentVersionRun_3fb5 {
  strings:
    $key_3fb5 = { 6c da [2] 48 d4 [2] 63 f8 [2] 4d da [2] 59 c1 [2] 56 db [2] 48 c6 [2] 4a c7 [2] 51 c1 [2] 4d c6 [2] 51 e9 }

  condition:
    any of them
}