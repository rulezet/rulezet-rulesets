rule TTP_XOR_QUAD_CurrentVersionRun_a16e {
  strings:
    $key_a16e = { f2 01 [2] d6 0f [2] fd 23 [2] d3 01 [2] c7 1a [2] c8 00 [2] d6 1d [2] d4 1c [2] cf 1a [2] d3 1d [2] cf 32 }

  condition:
    any of them
}