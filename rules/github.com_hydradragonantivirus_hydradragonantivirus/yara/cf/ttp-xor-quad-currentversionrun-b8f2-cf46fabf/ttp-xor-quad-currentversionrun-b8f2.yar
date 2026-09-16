rule TTP_XOR_QUAD_CurrentVersionRun_b8f2 {
  strings:
    $key_b8f2 = { eb 9d [2] cf 93 [2] e4 bf [2] ca 9d [2] de 86 [2] d1 9c [2] cf 81 [2] cd 80 [2] d6 86 [2] ca 81 [2] d6 ae }

  condition:
    any of them
}