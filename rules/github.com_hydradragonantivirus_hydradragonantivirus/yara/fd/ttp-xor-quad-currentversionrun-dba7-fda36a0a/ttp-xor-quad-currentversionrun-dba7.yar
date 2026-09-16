rule TTP_XOR_QUAD_CurrentVersionRun_dba7 {
  strings:
    $key_dba7 = { 88 c8 [2] ac c6 [2] 87 ea [2] a9 c8 [2] bd d3 [2] b2 c9 [2] ac d4 [2] ae d5 [2] b5 d3 [2] a9 d4 [2] b5 fb }

  condition:
    any of them
}