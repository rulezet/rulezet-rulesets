rule TTP_XOR_QUAD_CurrentVersionRun_404a {
  strings:
    $key_404a = { 13 25 [2] 37 2b [2] 1c 07 [2] 32 25 [2] 26 3e [2] 29 24 [2] 37 39 [2] 35 38 [2] 2e 3e [2] 32 39 [2] 2e 16 }

  condition:
    any of them
}