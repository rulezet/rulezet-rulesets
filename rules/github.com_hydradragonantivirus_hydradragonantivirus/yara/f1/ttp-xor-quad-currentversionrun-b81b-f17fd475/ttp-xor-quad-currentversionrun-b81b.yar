rule TTP_XOR_QUAD_CurrentVersionRun_b81b {
  strings:
    $key_b81b = { eb 74 [2] cf 7a [2] e4 56 [2] ca 74 [2] de 6f [2] d1 75 [2] cf 68 [2] cd 69 [2] d6 6f [2] ca 68 [2] d6 47 }

  condition:
    any of them
}