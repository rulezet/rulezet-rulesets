rule TTP_XOR_QUAD_CurrentVersionRun_24fb {
  strings:
    $key_24fb = { 77 94 [2] 53 9a [2] 78 b6 [2] 56 94 [2] 42 8f [2] 4d 95 [2] 53 88 [2] 51 89 [2] 4a 8f [2] 56 88 [2] 4a a7 }

  condition:
    any of them
}