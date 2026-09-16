rule TTP_XOR_QUAD_CurrentVersionRun_2eb5 {
  strings:
    $key_2eb5 = { 7d da [2] 59 d4 [2] 72 f8 [2] 5c da [2] 48 c1 [2] 47 db [2] 59 c6 [2] 5b c7 [2] 40 c1 [2] 5c c6 [2] 40 e9 }

  condition:
    any of them
}