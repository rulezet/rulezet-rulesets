rule TTP_XOR_QUAD_CurrentVersionRun_b870 {
  strings:
    $key_b870 = { eb 1f [2] cf 11 [2] e4 3d [2] ca 1f [2] de 04 [2] d1 1e [2] cf 03 [2] cd 02 [2] d6 04 [2] ca 03 [2] d6 2c }

  condition:
    any of them
}