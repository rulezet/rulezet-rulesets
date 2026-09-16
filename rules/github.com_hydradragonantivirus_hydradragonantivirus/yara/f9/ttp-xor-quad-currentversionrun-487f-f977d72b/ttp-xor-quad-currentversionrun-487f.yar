rule TTP_XOR_QUAD_CurrentVersionRun_487f {
  strings:
    $key_487f = { 1b 10 [2] 3f 1e [2] 14 32 [2] 3a 10 [2] 2e 0b [2] 21 11 [2] 3f 0c [2] 3d 0d [2] 26 0b [2] 3a 0c [2] 26 23 }

  condition:
    any of them
}