rule TTP_XOR_QUAD_CurrentVersionRun_b15e {
  strings:
    $key_b15e = { e2 31 [2] c6 3f [2] ed 13 [2] c3 31 [2] d7 2a [2] d8 30 [2] c6 2d [2] c4 2c [2] df 2a [2] c3 2d [2] df 02 }

  condition:
    any of them
}