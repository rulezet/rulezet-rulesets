rule TTP_XOR_QUAD_CurrentVersionRun_a641 {
  strings:
    $key_a641 = { f5 2e [2] d1 20 [2] fa 0c [2] d4 2e [2] c0 35 [2] cf 2f [2] d1 32 [2] d3 33 [2] c8 35 [2] d4 32 [2] c8 1d }

  condition:
    any of them
}