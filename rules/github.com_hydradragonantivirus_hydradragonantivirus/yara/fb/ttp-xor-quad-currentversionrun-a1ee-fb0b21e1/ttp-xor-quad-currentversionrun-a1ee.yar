rule TTP_XOR_QUAD_CurrentVersionRun_a1ee {
  strings:
    $key_a1ee = { f2 81 [2] d6 8f [2] fd a3 [2] d3 81 [2] c7 9a [2] c8 80 [2] d6 9d [2] d4 9c [2] cf 9a [2] d3 9d [2] cf b2 }

  condition:
    any of them
}