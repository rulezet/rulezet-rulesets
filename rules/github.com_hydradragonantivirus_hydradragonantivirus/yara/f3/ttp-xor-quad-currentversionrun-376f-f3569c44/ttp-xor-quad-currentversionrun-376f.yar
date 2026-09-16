rule TTP_XOR_QUAD_CurrentVersionRun_376f {
  strings:
    $key_376f = { 64 00 [2] 40 0e [2] 6b 22 [2] 45 00 [2] 51 1b [2] 5e 01 [2] 40 1c [2] 42 1d [2] 59 1b [2] 45 1c [2] 59 33 }

  condition:
    any of them
}