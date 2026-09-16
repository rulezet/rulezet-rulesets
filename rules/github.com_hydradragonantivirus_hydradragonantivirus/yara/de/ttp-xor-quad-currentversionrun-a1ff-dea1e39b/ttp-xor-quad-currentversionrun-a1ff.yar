rule TTP_XOR_QUAD_CurrentVersionRun_a1ff {
  strings:
    $key_a1ff = { f2 90 [2] d6 9e [2] fd b2 [2] d3 90 [2] c7 8b [2] c8 91 [2] d6 8c [2] d4 8d [2] cf 8b [2] d3 8c [2] cf a3 }

  condition:
    any of them
}