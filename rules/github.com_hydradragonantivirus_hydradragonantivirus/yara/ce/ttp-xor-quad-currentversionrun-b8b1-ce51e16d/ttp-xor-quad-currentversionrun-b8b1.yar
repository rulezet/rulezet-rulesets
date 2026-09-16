rule TTP_XOR_QUAD_CurrentVersionRun_b8b1 {
  strings:
    $key_b8b1 = { eb de [2] cf d0 [2] e4 fc [2] ca de [2] de c5 [2] d1 df [2] cf c2 [2] cd c3 [2] d6 c5 [2] ca c2 [2] d6 ed }

  condition:
    any of them
}