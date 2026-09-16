rule TTP_XOR_QUAD_CurrentVersionRun_216f {
  strings:
    $key_216f = { 72 00 [2] 56 0e [2] 7d 22 [2] 53 00 [2] 47 1b [2] 48 01 [2] 56 1c [2] 54 1d [2] 4f 1b [2] 53 1c [2] 4f 33 }

  condition:
    any of them
}