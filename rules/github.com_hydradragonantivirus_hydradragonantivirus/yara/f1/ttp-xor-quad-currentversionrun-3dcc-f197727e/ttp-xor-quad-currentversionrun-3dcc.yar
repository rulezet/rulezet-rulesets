rule TTP_XOR_QUAD_CurrentVersionRun_3dcc {
  strings:
    $key_3dcc = { 6e a3 [2] 4a ad [2] 61 81 [2] 4f a3 [2] 5b b8 [2] 54 a2 [2] 4a bf [2] 48 be [2] 53 b8 [2] 4f bf [2] 53 90 }

  condition:
    any of them
}