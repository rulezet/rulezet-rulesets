rule TTP_XOR_QUAD_CurrentVersionRun_b84a {
  strings:
    $key_b84a = { eb 25 [2] cf 2b [2] e4 07 [2] ca 25 [2] de 3e [2] d1 24 [2] cf 39 [2] cd 38 [2] d6 3e [2] ca 39 [2] d6 16 }

  condition:
    any of them
}