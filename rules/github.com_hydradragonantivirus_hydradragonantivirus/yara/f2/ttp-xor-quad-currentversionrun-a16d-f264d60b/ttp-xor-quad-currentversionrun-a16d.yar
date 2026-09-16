rule TTP_XOR_QUAD_CurrentVersionRun_a16d {
  strings:
    $key_a16d = { f2 02 [2] d6 0c [2] fd 20 [2] d3 02 [2] c7 19 [2] c8 03 [2] d6 1e [2] d4 1f [2] cf 19 [2] d3 1e [2] cf 31 }

  condition:
    any of them
}