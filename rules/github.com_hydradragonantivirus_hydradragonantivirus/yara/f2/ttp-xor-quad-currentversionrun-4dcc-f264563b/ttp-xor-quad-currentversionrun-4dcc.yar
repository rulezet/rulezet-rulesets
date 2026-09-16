rule TTP_XOR_QUAD_CurrentVersionRun_4dcc {
  strings:
    $key_4dcc = { 1e a3 [2] 3a ad [2] 11 81 [2] 3f a3 [2] 2b b8 [2] 24 a2 [2] 3a bf [2] 38 be [2] 23 b8 [2] 3f bf [2] 23 90 }

  condition:
    any of them
}