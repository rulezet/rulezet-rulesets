rule TTP_XOR_QUAD_CurrentVersionRun_314a {
  strings:
    $key_314a = { 62 25 [2] 46 2b [2] 6d 07 [2] 43 25 [2] 57 3e [2] 58 24 [2] 46 39 [2] 44 38 [2] 5f 3e [2] 43 39 [2] 5f 16 }

  condition:
    any of them
}