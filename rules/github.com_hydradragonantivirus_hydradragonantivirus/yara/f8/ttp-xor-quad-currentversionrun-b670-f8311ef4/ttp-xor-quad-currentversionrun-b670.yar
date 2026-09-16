rule TTP_XOR_QUAD_CurrentVersionRun_b670 {
  strings:
    $key_b670 = { e5 1f [2] c1 11 [2] ea 3d [2] c4 1f [2] d0 04 [2] df 1e [2] c1 03 [2] c3 02 [2] d8 04 [2] c4 03 [2] d8 2c }

  condition:
    any of them
}