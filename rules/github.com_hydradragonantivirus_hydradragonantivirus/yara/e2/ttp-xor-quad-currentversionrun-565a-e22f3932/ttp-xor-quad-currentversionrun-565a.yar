rule TTP_XOR_QUAD_CurrentVersionRun_565a {
  strings:
    $key_565a = { 05 35 [2] 21 3b [2] 0a 17 [2] 24 35 [2] 30 2e [2] 3f 34 [2] 21 29 [2] 23 28 [2] 38 2e [2] 24 29 [2] 38 06 }

  condition:
    any of them
}