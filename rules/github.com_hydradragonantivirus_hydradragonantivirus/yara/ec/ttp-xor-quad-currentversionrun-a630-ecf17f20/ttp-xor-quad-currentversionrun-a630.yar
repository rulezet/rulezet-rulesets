rule TTP_XOR_QUAD_CurrentVersionRun_a630 {
  strings:
    $key_a630 = { f5 5f [2] d1 51 [2] fa 7d [2] d4 5f [2] c0 44 [2] cf 5e [2] d1 43 [2] d3 42 [2] c8 44 [2] d4 43 [2] c8 6c }

  condition:
    any of them
}