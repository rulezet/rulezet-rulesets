rule TTP_XOR_QUAD_CurrentVersionRun_a113 {
  strings:
    $key_a113 = { f2 7c [2] d6 72 [2] fd 5e [2] d3 7c [2] c7 67 [2] c8 7d [2] d6 60 [2] d4 61 [2] cf 67 [2] d3 60 [2] cf 4f }

  condition:
    any of them
}