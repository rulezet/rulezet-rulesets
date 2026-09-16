rule TTP_XOR_QUAD_CurrentVersionRun_a15f {
  strings:
    $key_a15f = { f2 30 [2] d6 3e [2] fd 12 [2] d3 30 [2] c7 2b [2] c8 31 [2] d6 2c [2] d4 2d [2] cf 2b [2] d3 2c [2] cf 03 }

  condition:
    any of them
}