rule TTP_XOR_QUAD_CurrentVersionRun_a17d {
  strings:
    $key_a17d = { f2 12 [2] d6 1c [2] fd 30 [2] d3 12 [2] c7 09 [2] c8 13 [2] d6 0e [2] d4 0f [2] cf 09 [2] d3 0e [2] cf 21 }

  condition:
    any of them
}