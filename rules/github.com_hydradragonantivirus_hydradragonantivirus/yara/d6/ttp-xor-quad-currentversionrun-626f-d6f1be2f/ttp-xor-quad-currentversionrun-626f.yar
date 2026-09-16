rule TTP_XOR_QUAD_CurrentVersionRun_626f {
  strings:
    $key_626f = { 31 00 [2] 15 0e [2] 3e 22 [2] 10 00 [2] 04 1b [2] 0b 01 [2] 15 1c [2] 17 1d [2] 0c 1b [2] 10 1c [2] 0c 33 }

  condition:
    any of them
}