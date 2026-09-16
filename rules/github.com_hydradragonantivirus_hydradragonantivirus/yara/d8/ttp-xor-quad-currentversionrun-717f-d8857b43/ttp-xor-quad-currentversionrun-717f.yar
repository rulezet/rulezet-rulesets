rule TTP_XOR_QUAD_CurrentVersionRun_717f {
  strings:
    $key_717f = { 22 10 [2] 06 1e [2] 2d 32 [2] 03 10 [2] 17 0b [2] 18 11 [2] 06 0c [2] 04 0d [2] 1f 0b [2] 03 0c [2] 1f 23 }

  condition:
    any of them
}