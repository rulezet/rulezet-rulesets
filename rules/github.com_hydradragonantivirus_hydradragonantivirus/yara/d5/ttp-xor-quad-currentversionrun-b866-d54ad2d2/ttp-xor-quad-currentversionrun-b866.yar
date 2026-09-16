rule TTP_XOR_QUAD_CurrentVersionRun_b866 {
  strings:
    $key_b866 = { eb 09 [2] cf 07 [2] e4 2b [2] ca 09 [2] de 12 [2] d1 08 [2] cf 15 [2] cd 14 [2] d6 12 [2] ca 15 [2] d6 3a }

  condition:
    any of them
}