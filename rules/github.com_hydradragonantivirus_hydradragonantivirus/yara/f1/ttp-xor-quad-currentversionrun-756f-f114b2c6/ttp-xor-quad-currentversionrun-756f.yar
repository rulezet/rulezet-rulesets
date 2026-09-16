rule TTP_XOR_QUAD_CurrentVersionRun_756f {
  strings:
    $key_756f = { 26 00 [2] 02 0e [2] 29 22 [2] 07 00 [2] 13 1b [2] 1c 01 [2] 02 1c [2] 00 1d [2] 1b 1b [2] 07 1c [2] 1b 33 }

  condition:
    any of them
}