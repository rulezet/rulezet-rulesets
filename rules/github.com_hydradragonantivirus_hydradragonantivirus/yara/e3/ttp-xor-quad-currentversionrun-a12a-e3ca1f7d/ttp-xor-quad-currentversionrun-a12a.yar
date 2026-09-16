rule TTP_XOR_QUAD_CurrentVersionRun_a12a {
  strings:
    $key_a12a = { f2 45 [2] d6 4b [2] fd 67 [2] d3 45 [2] c7 5e [2] c8 44 [2] d6 59 [2] d4 58 [2] cf 5e [2] d3 59 [2] cf 76 }

  condition:
    any of them
}