rule TTP_XOR_QUAD_CurrentVersionRun_14b4 {
  strings:
    $key_14b4 = { 47 db [2] 63 d5 [2] 48 f9 [2] 66 db [2] 72 c0 [2] 7d da [2] 63 c7 [2] 61 c6 [2] 7a c0 [2] 66 c7 [2] 7a e8 }

  condition:
    any of them
}