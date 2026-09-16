rule TTP_XOR_QUAD_CurrentVersionRun_740f {
  strings:
    $key_740f = { 27 60 [2] 03 6e [2] 28 42 [2] 06 60 [2] 12 7b [2] 1d 61 [2] 03 7c [2] 01 7d [2] 1a 7b [2] 06 7c [2] 1a 53 }

  condition:
    any of them
}