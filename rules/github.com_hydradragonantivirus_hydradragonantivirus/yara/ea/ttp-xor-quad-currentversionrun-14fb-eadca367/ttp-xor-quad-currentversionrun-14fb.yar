rule TTP_XOR_QUAD_CurrentVersionRun_14fb {
  strings:
    $key_14fb = { 47 94 [2] 63 9a [2] 48 b6 [2] 66 94 [2] 72 8f [2] 7d 95 [2] 63 88 [2] 61 89 [2] 7a 8f [2] 66 88 [2] 7a a7 }

  condition:
    any of them
}