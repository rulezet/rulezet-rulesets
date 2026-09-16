rule TTP_XOR_QUAD_CurrentVersionRun_b65c {
  strings:
    $key_b65c = { e5 33 [2] c1 3d [2] ea 11 [2] c4 33 [2] d0 28 [2] df 32 [2] c1 2f [2] c3 2e [2] d8 28 [2] c4 2f [2] d8 00 }

  condition:
    any of them
}