rule TTP_XOR_QUAD_CurrentVersionRun_a61f {
  strings:
    $key_a61f = { f5 70 [2] d1 7e [2] fa 52 [2] d4 70 [2] c0 6b [2] cf 71 [2] d1 6c [2] d3 6d [2] c8 6b [2] d4 6c [2] c8 43 }

  condition:
    any of them
}