rule TTP_XOR_QUAD_CurrentVersionRun_7b4a {
  strings:
    $key_7b4a = { 28 25 [2] 0c 2b [2] 27 07 [2] 09 25 [2] 1d 3e [2] 12 24 [2] 0c 39 [2] 0e 38 [2] 15 3e [2] 09 39 [2] 15 16 }

  condition:
    any of them
}