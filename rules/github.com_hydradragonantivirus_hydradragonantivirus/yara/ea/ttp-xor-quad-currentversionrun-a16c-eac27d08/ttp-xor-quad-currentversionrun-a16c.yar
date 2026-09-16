rule TTP_XOR_QUAD_CurrentVersionRun_a16c {
  strings:
    $key_a16c = { f2 03 [2] d6 0d [2] fd 21 [2] d3 03 [2] c7 18 [2] c8 02 [2] d6 1f [2] d4 1e [2] cf 18 [2] d3 1f [2] cf 30 }

  condition:
    any of them
}