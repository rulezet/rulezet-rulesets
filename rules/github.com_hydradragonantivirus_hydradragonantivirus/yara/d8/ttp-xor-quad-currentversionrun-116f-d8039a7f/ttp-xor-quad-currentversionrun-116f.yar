rule TTP_XOR_QUAD_CurrentVersionRun_116f {
  strings:
    $key_116f = { 42 00 [2] 66 0e [2] 4d 22 [2] 63 00 [2] 77 1b [2] 78 01 [2] 66 1c [2] 64 1d [2] 7f 1b [2] 63 1c [2] 7f 33 }

  condition:
    any of them
}