rule TTP_XOR_QUAD_CurrentVersionRun_e2f6 {
  strings:
    $key_e2f6 = { b1 99 [2] 95 97 [2] be bb [2] 90 99 [2] 84 82 [2] 8b 98 [2] 95 85 [2] 97 84 [2] 8c 82 [2] 90 85 [2] 8c aa }

  condition:
    any of them
}