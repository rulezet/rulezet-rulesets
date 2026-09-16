rule TTP_XOR_QUAD_CurrentVersionRun_b8d2 {
  strings:
    $key_b8d2 = { eb bd [2] cf b3 [2] e4 9f [2] ca bd [2] de a6 [2] d1 bc [2] cf a1 [2] cd a0 [2] d6 a6 [2] ca a1 [2] d6 8e }

  condition:
    any of them
}