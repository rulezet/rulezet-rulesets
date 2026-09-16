rule TTP_XOR_QUAD_CurrentVersionRun_bfae {
  strings:
    $key_bfae = { ec c1 [2] c8 cf [2] e3 e3 [2] cd c1 [2] d9 da [2] d6 c0 [2] c8 dd [2] ca dc [2] d1 da [2] cd dd [2] d1 f2 }

  condition:
    any of them
}