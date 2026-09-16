rule TTP_XOR_QUAD_CurrentVersionRun_777f {
  strings:
    $key_777f = { 24 10 [2] 00 1e [2] 2b 32 [2] 05 10 [2] 11 0b [2] 1e 11 [2] 00 0c [2] 02 0d [2] 19 0b [2] 05 0c [2] 19 23 }

  condition:
    any of them
}