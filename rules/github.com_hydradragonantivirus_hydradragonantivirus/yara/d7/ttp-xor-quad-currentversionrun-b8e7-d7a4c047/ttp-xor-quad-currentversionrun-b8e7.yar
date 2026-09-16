rule TTP_XOR_QUAD_CurrentVersionRun_b8e7 {
  strings:
    $key_b8e7 = { eb 88 [2] cf 86 [2] e4 aa [2] ca 88 [2] de 93 [2] d1 89 [2] cf 94 [2] cd 95 [2] d6 93 [2] ca 94 [2] d6 bb }

  condition:
    any of them
}