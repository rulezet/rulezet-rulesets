rule TTP_XOR_QUAD_CurrentVersionRun_4c6a {
  strings:
    $key_4c6a = { 1f 05 [2] 3b 0b [2] 10 27 [2] 3e 05 [2] 2a 1e [2] 25 04 [2] 3b 19 [2] 39 18 [2] 22 1e [2] 3e 19 [2] 22 36 }

  condition:
    any of them
}