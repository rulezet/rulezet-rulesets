rule TTP_XOR_QUAD_CurrentVersionRun_9ad1 {
  strings:
    $key_9ad1 = { c9 be [2] ed b0 [2] c6 9c [2] e8 be [2] fc a5 [2] f3 bf [2] ed a2 [2] ef a3 [2] f4 a5 [2] e8 a2 [2] f4 8d }

  condition:
    any of them
}