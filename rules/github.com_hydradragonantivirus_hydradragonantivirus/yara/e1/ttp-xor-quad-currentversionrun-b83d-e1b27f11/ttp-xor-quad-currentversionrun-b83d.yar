rule TTP_XOR_QUAD_CurrentVersionRun_b83d {
  strings:
    $key_b83d = { eb 52 [2] cf 5c [2] e4 70 [2] ca 52 [2] de 49 [2] d1 53 [2] cf 4e [2] cd 4f [2] d6 49 [2] ca 4e [2] d6 61 }

  condition:
    any of them
}