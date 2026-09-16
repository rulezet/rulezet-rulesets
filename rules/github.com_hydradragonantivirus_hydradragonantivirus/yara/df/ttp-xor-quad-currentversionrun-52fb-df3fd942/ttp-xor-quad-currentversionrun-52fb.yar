rule TTP_XOR_QUAD_CurrentVersionRun_52fb {
  strings:
    $key_52fb = { 01 94 [2] 25 9a [2] 0e b6 [2] 20 94 [2] 34 8f [2] 3b 95 [2] 25 88 [2] 27 89 [2] 3c 8f [2] 20 88 [2] 3c a7 }

  condition:
    any of them
}