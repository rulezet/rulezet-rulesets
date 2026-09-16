rule TTP_XOR_QUAD_CurrentVersionRun_a3d2 {
  strings:
    $key_a3d2 = { f0 bd [2] d4 b3 [2] ff 9f [2] d1 bd [2] c5 a6 [2] ca bc [2] d4 a1 [2] d6 a0 [2] cd a6 [2] d1 a1 [2] cd 8e }

  condition:
    any of them
}