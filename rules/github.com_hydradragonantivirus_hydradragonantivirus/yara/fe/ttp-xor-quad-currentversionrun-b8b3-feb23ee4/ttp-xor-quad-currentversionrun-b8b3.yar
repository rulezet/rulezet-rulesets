rule TTP_XOR_QUAD_CurrentVersionRun_b8b3 {
  strings:
    $key_b8b3 = { eb dc [2] cf d2 [2] e4 fe [2] ca dc [2] de c7 [2] d1 dd [2] cf c0 [2] cd c1 [2] d6 c7 [2] ca c0 [2] d6 ef }

  condition:
    any of them
}