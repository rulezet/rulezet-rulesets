rule TTP_XOR_QUAD_CurrentVersionRun_3e6f {
  strings:
    $key_3e6f = { 6d 00 [2] 49 0e [2] 62 22 [2] 4c 00 [2] 58 1b [2] 57 01 [2] 49 1c [2] 4b 1d [2] 50 1b [2] 4c 1c [2] 50 33 }

  condition:
    any of them
}