rule TTP_XOR_QUAD_CurrentVersionRun_596a {
  strings:
    $key_596a = { 0a 05 [2] 2e 0b [2] 05 27 [2] 2b 05 [2] 3f 1e [2] 30 04 [2] 2e 19 [2] 2c 18 [2] 37 1e [2] 2b 19 [2] 37 36 }

  condition:
    any of them
}