rule TTP_XOR_QUAD_CurrentVersionRun_742f {
  strings:
    $key_742f = { 27 40 [2] 03 4e [2] 28 62 [2] 06 40 [2] 12 5b [2] 1d 41 [2] 03 5c [2] 01 5d [2] 1a 5b [2] 06 5c [2] 1a 73 }

  condition:
    any of them
}