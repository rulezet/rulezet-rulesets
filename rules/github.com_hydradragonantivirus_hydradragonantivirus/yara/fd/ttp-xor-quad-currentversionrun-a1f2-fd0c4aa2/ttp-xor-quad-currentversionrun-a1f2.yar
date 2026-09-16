rule TTP_XOR_QUAD_CurrentVersionRun_a1f2 {
  strings:
    $key_a1f2 = { f2 9d [2] d6 93 [2] fd bf [2] d3 9d [2] c7 86 [2] c8 9c [2] d6 81 [2] d4 80 [2] cf 86 [2] d3 81 [2] cf ae }

  condition:
    any of them
}