rule TTP_XOR_QUAD_CurrentVersionRun_b65f {
  strings:
    $key_b65f = { e5 30 [2] c1 3e [2] ea 12 [2] c4 30 [2] d0 2b [2] df 31 [2] c1 2c [2] c3 2d [2] d8 2b [2] c4 2c [2] d8 03 }

  condition:
    any of them
}