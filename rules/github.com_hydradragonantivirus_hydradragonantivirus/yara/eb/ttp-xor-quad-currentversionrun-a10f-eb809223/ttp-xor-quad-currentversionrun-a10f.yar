rule TTP_XOR_QUAD_CurrentVersionRun_a10f {
  strings:
    $key_a10f = { f2 60 [2] d6 6e [2] fd 42 [2] d3 60 [2] c7 7b [2] c8 61 [2] d6 7c [2] d4 7d [2] cf 7b [2] d3 7c [2] cf 53 }

  condition:
    any of them
}