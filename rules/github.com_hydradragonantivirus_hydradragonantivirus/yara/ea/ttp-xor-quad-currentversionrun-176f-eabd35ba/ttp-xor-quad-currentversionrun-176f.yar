rule TTP_XOR_QUAD_CurrentVersionRun_176f {
  strings:
    $key_176f = { 44 00 [2] 60 0e [2] 4b 22 [2] 65 00 [2] 71 1b [2] 7e 01 [2] 60 1c [2] 62 1d [2] 79 1b [2] 65 1c [2] 79 33 }

  condition:
    any of them
}