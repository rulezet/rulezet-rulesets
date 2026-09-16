rule TTP_XOR_QUAD_CurrentVersionRun_ab5f {
  strings:
    $key_ab5f = { f8 30 [2] dc 3e [2] f7 12 [2] d9 30 [2] cd 2b [2] c2 31 [2] dc 2c [2] de 2d [2] c5 2b [2] d9 2c [2] c5 03 }

  condition:
    any of them
}