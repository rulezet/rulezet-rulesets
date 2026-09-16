rule TTP_XOR_QUAD_CurrentVersionRun_b82e {
  strings:
    $key_b82e = { eb 41 [2] cf 4f [2] e4 63 [2] ca 41 [2] de 5a [2] d1 40 [2] cf 5d [2] cd 5c [2] d6 5a [2] ca 5d [2] d6 72 }

  condition:
    any of them
}