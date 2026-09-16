rule TTP_XOR_QUAD_CurrentVersionRun_0da6 {
  strings:
    $key_0da6 = { 5e c9 [2] 7a c7 [2] 51 eb [2] 7f c9 [2] 6b d2 [2] 64 c8 [2] 7a d5 [2] 78 d4 [2] 63 d2 [2] 7f d5 [2] 63 fa }

  condition:
    any of them
}