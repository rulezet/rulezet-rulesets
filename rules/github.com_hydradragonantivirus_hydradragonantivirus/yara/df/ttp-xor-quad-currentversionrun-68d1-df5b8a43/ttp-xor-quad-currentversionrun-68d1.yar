rule TTP_XOR_QUAD_CurrentVersionRun_68d1 {
  strings:
    $key_68d1 = { 3b be [2] 1f b0 [2] 34 9c [2] 1a be [2] 0e a5 [2] 01 bf [2] 1f a2 [2] 1d a3 [2] 06 a5 [2] 1a a2 [2] 06 8d }

  condition:
    any of them
}