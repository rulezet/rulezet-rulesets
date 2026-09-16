rule TTP_XOR_QUAD_CurrentVersionRun_11fb {
  strings:
    $key_11fb = { 42 94 [2] 66 9a [2] 4d b6 [2] 63 94 [2] 77 8f [2] 78 95 [2] 66 88 [2] 64 89 [2] 7f 8f [2] 63 88 [2] 7f a7 }

  condition:
    any of them
}