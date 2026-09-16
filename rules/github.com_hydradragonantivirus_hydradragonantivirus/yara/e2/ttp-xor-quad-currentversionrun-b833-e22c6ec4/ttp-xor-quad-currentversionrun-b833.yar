rule TTP_XOR_QUAD_CurrentVersionRun_b833 {
  strings:
    $key_b833 = { eb 5c [2] cf 52 [2] e4 7e [2] ca 5c [2] de 47 [2] d1 5d [2] cf 40 [2] cd 41 [2] d6 47 [2] ca 40 [2] d6 6f }

  condition:
    any of them
}