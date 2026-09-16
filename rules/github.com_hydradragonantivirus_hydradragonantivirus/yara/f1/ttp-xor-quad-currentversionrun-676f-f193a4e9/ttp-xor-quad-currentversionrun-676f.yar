rule TTP_XOR_QUAD_CurrentVersionRun_676f {
  strings:
    $key_676f = { 34 00 [2] 10 0e [2] 3b 22 [2] 15 00 [2] 01 1b [2] 0e 01 [2] 10 1c [2] 12 1d [2] 09 1b [2] 15 1c [2] 09 33 }

  condition:
    any of them
}