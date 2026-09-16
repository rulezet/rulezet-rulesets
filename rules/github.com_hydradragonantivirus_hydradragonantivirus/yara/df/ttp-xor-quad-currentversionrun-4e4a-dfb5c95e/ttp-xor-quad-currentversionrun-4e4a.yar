rule TTP_XOR_QUAD_CurrentVersionRun_4e4a {
  strings:
    $key_4e4a = { 1d 25 [2] 39 2b [2] 12 07 [2] 3c 25 [2] 28 3e [2] 27 24 [2] 39 39 [2] 3b 38 [2] 20 3e [2] 3c 39 [2] 20 16 }

  condition:
    any of them
}