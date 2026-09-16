rule TTP_XOR_QUAD_CurrentVersionRun_7c6f {
  strings:
    $key_7c6f = { 2f 00 [2] 0b 0e [2] 20 22 [2] 0e 00 [2] 1a 1b [2] 15 01 [2] 0b 1c [2] 09 1d [2] 12 1b [2] 0e 1c [2] 12 33 }

  condition:
    any of them
}