rule TTP_XOR_QUAD_CurrentVersionRun_a114 {
  strings:
    $key_a114 = { f2 7b [2] d6 75 [2] fd 59 [2] d3 7b [2] c7 60 [2] c8 7a [2] d6 67 [2] d4 66 [2] cf 60 [2] d3 67 [2] cf 48 }

  condition:
    any of them
}