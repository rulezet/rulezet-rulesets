rule TTP_XOR_QUAD_CurrentVersionRun_40fb {
  strings:
    $key_40fb = { 13 94 [2] 37 9a [2] 1c b6 [2] 32 94 [2] 26 8f [2] 29 95 [2] 37 88 [2] 35 89 [2] 2e 8f [2] 32 88 [2] 2e a7 }

  condition:
    any of them
}