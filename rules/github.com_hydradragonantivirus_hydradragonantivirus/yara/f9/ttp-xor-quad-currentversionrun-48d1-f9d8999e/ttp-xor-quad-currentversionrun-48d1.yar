rule TTP_XOR_QUAD_CurrentVersionRun_48d1 {
  strings:
    $key_48d1 = { 1b be [2] 3f b0 [2] 14 9c [2] 3a be [2] 2e a5 [2] 21 bf [2] 3f a2 [2] 3d a3 [2] 26 a5 [2] 3a a2 [2] 26 8d }

  condition:
    any of them
}