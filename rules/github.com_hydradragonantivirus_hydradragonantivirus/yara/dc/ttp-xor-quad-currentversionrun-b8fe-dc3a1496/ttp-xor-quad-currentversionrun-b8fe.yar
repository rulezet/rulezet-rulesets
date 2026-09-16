rule TTP_XOR_QUAD_CurrentVersionRun_b8fe {
  strings:
    $key_b8fe = { eb 91 [2] cf 9f [2] e4 b3 [2] ca 91 [2] de 8a [2] d1 90 [2] cf 8d [2] cd 8c [2] d6 8a [2] ca 8d [2] d6 a2 }

  condition:
    any of them
}