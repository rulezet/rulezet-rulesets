rule TTP_XOR_QUAD_CurrentVersionRun_a1cb {
  strings:
    $key_a1cb = { f2 a4 [2] d6 aa [2] fd 86 [2] d3 a4 [2] c7 bf [2] c8 a5 [2] d6 b8 [2] d4 b9 [2] cf bf [2] d3 b8 [2] cf 97 }

  condition:
    any of them
}