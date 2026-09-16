rule TTP_XOR_QUAD_CurrentVersionRun_bfd1 {
  strings:
    $key_bfd1 = { ec be [2] c8 b0 [2] e3 9c [2] cd be [2] d9 a5 [2] d6 bf [2] c8 a2 [2] ca a3 [2] d1 a5 [2] cd a2 [2] d1 8d }

  condition:
    any of them
}