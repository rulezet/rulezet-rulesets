rule TTP_XOR_QUAD_CurrentVersionRun_83cc {
  strings:
    $key_83cc = { d0 a3 [2] f4 ad [2] df 81 [2] f1 a3 [2] e5 b8 [2] ea a2 [2] f4 bf [2] f6 be [2] ed b8 [2] f1 bf [2] ed 90 }

  condition:
    any of them
}