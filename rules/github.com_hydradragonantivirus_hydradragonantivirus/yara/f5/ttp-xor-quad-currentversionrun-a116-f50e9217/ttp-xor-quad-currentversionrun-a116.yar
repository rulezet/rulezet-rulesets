rule TTP_XOR_QUAD_CurrentVersionRun_a116 {
  strings:
    $key_a116 = { f2 79 [2] d6 77 [2] fd 5b [2] d3 79 [2] c7 62 [2] c8 78 [2] d6 65 [2] d4 64 [2] cf 62 [2] d3 65 [2] cf 4a }

  condition:
    any of them
}