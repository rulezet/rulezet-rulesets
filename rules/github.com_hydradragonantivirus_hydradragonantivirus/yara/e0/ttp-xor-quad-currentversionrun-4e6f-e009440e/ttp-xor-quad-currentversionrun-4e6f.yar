rule TTP_XOR_QUAD_CurrentVersionRun_4e6f {
  strings:
    $key_4e6f = { 1d 00 [2] 39 0e [2] 12 22 [2] 3c 00 [2] 28 1b [2] 27 01 [2] 39 1c [2] 3b 1d [2] 20 1b [2] 3c 1c [2] 20 33 }

  condition:
    any of them
}