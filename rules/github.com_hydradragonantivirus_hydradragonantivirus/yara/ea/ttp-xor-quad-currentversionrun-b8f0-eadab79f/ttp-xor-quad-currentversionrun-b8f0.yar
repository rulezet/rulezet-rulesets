rule TTP_XOR_QUAD_CurrentVersionRun_b8f0 {
  strings:
    $key_b8f0 = { eb 9f [2] cf 91 [2] e4 bd [2] ca 9f [2] de 84 [2] d1 9e [2] cf 83 [2] cd 82 [2] d6 84 [2] ca 83 [2] d6 ac }

  condition:
    any of them
}