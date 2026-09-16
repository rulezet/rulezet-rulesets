rule TTP_XOR_QUAD_CurrentVersionRun_a1fc {
  strings:
    $key_a1fc = { f2 93 [2] d6 9d [2] fd b1 [2] d3 93 [2] c7 88 [2] c8 92 [2] d6 8f [2] d4 8e [2] cf 88 [2] d3 8f [2] cf a0 }

  condition:
    any of them
}