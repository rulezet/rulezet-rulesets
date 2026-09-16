rule TTP_XOR_QUAD_CurrentVersionRun_2dcc {
  strings:
    $key_2dcc = { 7e a3 [2] 5a ad [2] 71 81 [2] 5f a3 [2] 4b b8 [2] 44 a2 [2] 5a bf [2] 58 be [2] 43 b8 [2] 5f bf [2] 43 90 }

  condition:
    any of them
}