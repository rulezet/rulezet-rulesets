rule TTP_XOR_QUAD_CurrentVersionRun_a1c0 {
  strings:
    $key_a1c0 = { f2 af [2] d6 a1 [2] fd 8d [2] d3 af [2] c7 b4 [2] c8 ae [2] d6 b3 [2] d4 b2 [2] cf b4 [2] d3 b3 [2] cf 9c }

  condition:
    any of them
}