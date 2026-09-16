rule TTP_XOR_QUAD_CurrentVersionRun_a3d1 {
  strings:
    $key_a3d1 = { f0 be [2] d4 b0 [2] ff 9c [2] d1 be [2] c5 a5 [2] ca bf [2] d4 a2 [2] d6 a3 [2] cd a5 [2] d1 a2 [2] cd 8d }

  condition:
    any of them
}