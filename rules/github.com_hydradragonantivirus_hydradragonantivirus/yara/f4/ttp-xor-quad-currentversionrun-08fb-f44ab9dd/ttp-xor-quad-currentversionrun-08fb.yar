rule TTP_XOR_QUAD_CurrentVersionRun_08fb {
  strings:
    $key_08fb = { 5b 94 [2] 7f 9a [2] 54 b6 [2] 7a 94 [2] 6e 8f [2] 61 95 [2] 7f 88 [2] 7d 89 [2] 66 8f [2] 7a 88 [2] 66 a7 }

  condition:
    any of them
}