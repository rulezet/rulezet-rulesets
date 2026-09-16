rule TTP_XOR_QUAD_CurrentVersionRun_b770 {
  strings:
    $key_b770 = { e4 1f [2] c0 11 [2] eb 3d [2] c5 1f [2] d1 04 [2] de 1e [2] c0 03 [2] c2 02 [2] d9 04 [2] c5 03 [2] d9 2c }

  condition:
    any of them
}