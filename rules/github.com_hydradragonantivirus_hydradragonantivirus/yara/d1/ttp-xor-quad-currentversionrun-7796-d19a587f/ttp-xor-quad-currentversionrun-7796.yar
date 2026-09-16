rule TTP_XOR_QUAD_CurrentVersionRun_7796 {
  strings:
    $key_7796 = { 24 f9 [2] 00 f7 [2] 2b db [2] 05 f9 [2] 11 e2 [2] 1e f8 [2] 00 e5 [2] 02 e4 [2] 19 e2 [2] 05 e5 [2] 19 ca }

  condition:
    any of them
}