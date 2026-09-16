rule TTP_XOR_QUAD_CurrentVersionRun_a12d {
  strings:
    $key_a12d = { f2 42 [2] d6 4c [2] fd 60 [2] d3 42 [2] c7 59 [2] c8 43 [2] d6 5e [2] d4 5f [2] cf 59 [2] d3 5e [2] cf 71 }

  condition:
    any of them
}