rule TTP_XOR_QUAD_CurrentVersionRun_a61c {
  strings:
    $key_a61c = { f5 73 [2] d1 7d [2] fa 51 [2] d4 73 [2] c0 68 [2] cf 72 [2] d1 6f [2] d3 6e [2] c8 68 [2] d4 6f [2] c8 40 }

  condition:
    any of them
}