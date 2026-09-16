rule TTP_XOR_QUAD_CurrentVersionRun_076f {
  strings:
    $key_076f = { 54 00 [2] 70 0e [2] 5b 22 [2] 75 00 [2] 61 1b [2] 6e 01 [2] 70 1c [2] 72 1d [2] 69 1b [2] 75 1c [2] 69 33 }

  condition:
    any of them
}