rule TTP_XOR_QUAD_CurrentVersionRun_a75f {
  strings:
    $key_a75f = { f4 30 [2] d0 3e [2] fb 12 [2] d5 30 [2] c1 2b [2] ce 31 [2] d0 2c [2] d2 2d [2] c9 2b [2] d5 2c [2] c9 03 }

  condition:
    any of them
}