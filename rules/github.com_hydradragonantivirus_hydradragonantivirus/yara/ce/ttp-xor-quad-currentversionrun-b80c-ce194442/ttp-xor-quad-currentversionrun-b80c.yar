rule TTP_XOR_QUAD_CurrentVersionRun_b80c {
  strings:
    $key_b80c = { eb 63 [2] cf 6d [2] e4 41 [2] ca 63 [2] de 78 [2] d1 62 [2] cf 7f [2] cd 7e [2] d6 78 [2] ca 7f [2] d6 50 }

  condition:
    any of them
}