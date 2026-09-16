rule TTP_XOR_QUAD_CurrentVersionRun_730a {
  strings:
    $key_730a = { 20 65 [2] 04 6b [2] 2f 47 [2] 01 65 [2] 15 7e [2] 1a 64 [2] 04 79 [2] 06 78 [2] 1d 7e [2] 01 79 [2] 1d 56 }

  condition:
    any of them
}