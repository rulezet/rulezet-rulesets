rule TTP_XOR_QUAD_CurrentVersionRun_a770 {
  strings:
    $key_a770 = { f4 1f [2] d0 11 [2] fb 3d [2] d5 1f [2] c1 04 [2] ce 1e [2] d0 03 [2] d2 02 [2] c9 04 [2] d5 03 [2] c9 2c }

  condition:
    any of them
}