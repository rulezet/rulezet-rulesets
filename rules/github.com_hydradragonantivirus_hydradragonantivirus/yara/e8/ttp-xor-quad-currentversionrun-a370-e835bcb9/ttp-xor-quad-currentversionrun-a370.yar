rule TTP_XOR_QUAD_CurrentVersionRun_a370 {
  strings:
    $key_a370 = { f0 1f [2] d4 11 [2] ff 3d [2] d1 1f [2] c5 04 [2] ca 1e [2] d4 03 [2] d6 02 [2] cd 04 [2] d1 03 [2] cd 2c }

  condition:
    any of them
}