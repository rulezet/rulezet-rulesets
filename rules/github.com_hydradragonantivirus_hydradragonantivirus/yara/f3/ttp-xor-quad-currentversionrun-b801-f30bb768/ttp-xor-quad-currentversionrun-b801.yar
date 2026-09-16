rule TTP_XOR_QUAD_CurrentVersionRun_b801 {
  strings:
    $key_b801 = { eb 6e [2] cf 60 [2] e4 4c [2] ca 6e [2] de 75 [2] d1 6f [2] cf 72 [2] cd 73 [2] d6 75 [2] ca 72 [2] d6 5d }

  condition:
    any of them
}