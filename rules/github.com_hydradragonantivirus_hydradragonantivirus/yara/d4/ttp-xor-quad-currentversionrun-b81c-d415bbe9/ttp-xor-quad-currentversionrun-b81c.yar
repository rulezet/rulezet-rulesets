rule TTP_XOR_QUAD_CurrentVersionRun_b81c {
  strings:
    $key_b81c = { eb 73 [2] cf 7d [2] e4 51 [2] ca 73 [2] de 68 [2] d1 72 [2] cf 6f [2] cd 6e [2] d6 68 [2] ca 6f [2] d6 40 }

  condition:
    any of them
}