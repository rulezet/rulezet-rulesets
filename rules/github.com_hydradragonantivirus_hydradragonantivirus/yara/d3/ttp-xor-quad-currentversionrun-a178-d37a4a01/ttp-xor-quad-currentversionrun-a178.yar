rule TTP_XOR_QUAD_CurrentVersionRun_a178 {
  strings:
    $key_a178 = { f2 17 [2] d6 19 [2] fd 35 [2] d3 17 [2] c7 0c [2] c8 16 [2] d6 0b [2] d4 0a [2] cf 0c [2] d3 0b [2] cf 24 }

  condition:
    any of them
}