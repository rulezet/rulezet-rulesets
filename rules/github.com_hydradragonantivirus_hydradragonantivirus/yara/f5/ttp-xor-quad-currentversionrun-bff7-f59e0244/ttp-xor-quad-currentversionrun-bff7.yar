rule TTP_XOR_QUAD_CurrentVersionRun_bff7 {
  strings:
    $key_bff7 = { ec 98 [2] c8 96 [2] e3 ba [2] cd 98 [2] d9 83 [2] d6 99 [2] c8 84 [2] ca 85 [2] d1 83 [2] cd 84 [2] d1 ab }

  condition:
    any of them
}