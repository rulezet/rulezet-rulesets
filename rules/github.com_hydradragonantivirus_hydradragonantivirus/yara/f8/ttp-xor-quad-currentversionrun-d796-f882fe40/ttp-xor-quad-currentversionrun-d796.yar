rule TTP_XOR_QUAD_CurrentVersionRun_d796 {
  strings:
    $key_d796 = { 84 f9 [2] a0 f7 [2] 8b db [2] a5 f9 [2] b1 e2 [2] be f8 [2] a0 e5 [2] a2 e4 [2] b9 e2 [2] a5 e5 [2] b9 ca }

  condition:
    any of them
}