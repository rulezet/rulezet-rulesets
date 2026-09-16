rule TTP_XOR_QUAD_CurrentVersionRun_0b6f {
  strings:
    $key_0b6f = { 58 00 [2] 7c 0e [2] 57 22 [2] 79 00 [2] 6d 1b [2] 62 01 [2] 7c 1c [2] 7e 1d [2] 65 1b [2] 79 1c [2] 65 33 }

  condition:
    any of them
}