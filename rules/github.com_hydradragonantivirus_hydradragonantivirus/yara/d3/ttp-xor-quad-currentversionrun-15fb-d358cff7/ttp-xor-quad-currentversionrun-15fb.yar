rule TTP_XOR_QUAD_CurrentVersionRun_15fb {
  strings:
    $key_15fb = { 46 94 [2] 62 9a [2] 49 b6 [2] 67 94 [2] 73 8f [2] 7c 95 [2] 62 88 [2] 60 89 [2] 7b 8f [2] 67 88 [2] 7b a7 }

  condition:
    any of them
}