rule TTP_XOR_QUAD_CurrentVersionRun_bfb3 {
  strings:
    $key_bfb3 = { ec dc [2] c8 d2 [2] e3 fe [2] cd dc [2] d9 c7 [2] d6 dd [2] c8 c0 [2] ca c1 [2] d1 c7 [2] cd c0 [2] d1 ef }

  condition:
    any of them
}