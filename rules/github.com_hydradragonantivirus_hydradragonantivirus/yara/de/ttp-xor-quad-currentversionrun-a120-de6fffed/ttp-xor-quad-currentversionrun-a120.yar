rule TTP_XOR_QUAD_CurrentVersionRun_a120 {
  strings:
    $key_a120 = { f2 4f [2] d6 41 [2] fd 6d [2] d3 4f [2] c7 54 [2] c8 4e [2] d6 53 [2] d4 52 [2] cf 54 [2] d3 53 [2] cf 7c }

  condition:
    any of them
}