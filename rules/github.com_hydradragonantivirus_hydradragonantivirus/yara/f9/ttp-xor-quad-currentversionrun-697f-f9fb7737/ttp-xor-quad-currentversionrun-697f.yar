rule TTP_XOR_QUAD_CurrentVersionRun_697f {
  strings:
    $key_697f = { 3a 10 [2] 1e 1e [2] 35 32 [2] 1b 10 [2] 0f 0b [2] 00 11 [2] 1e 0c [2] 1c 0d [2] 07 0b [2] 1b 0c [2] 07 23 }

  condition:
    any of them
}