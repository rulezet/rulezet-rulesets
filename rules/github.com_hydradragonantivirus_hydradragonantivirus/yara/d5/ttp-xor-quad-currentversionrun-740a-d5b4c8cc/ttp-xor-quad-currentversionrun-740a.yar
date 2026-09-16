rule TTP_XOR_QUAD_CurrentVersionRun_740a {
  strings:
    $key_740a = { 27 65 [2] 03 6b [2] 28 47 [2] 06 65 [2] 12 7e [2] 1d 64 [2] 03 79 [2] 01 78 [2] 1a 7e [2] 06 79 [2] 1a 56 }

  condition:
    any of them
}