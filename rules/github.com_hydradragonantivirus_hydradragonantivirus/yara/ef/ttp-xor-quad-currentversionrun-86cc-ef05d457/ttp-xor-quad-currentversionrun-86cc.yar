rule TTP_XOR_QUAD_CurrentVersionRun_86cc {
  strings:
    $key_86cc = { d5 a3 [2] f1 ad [2] da 81 [2] f4 a3 [2] e0 b8 [2] ef a2 [2] f1 bf [2] f3 be [2] e8 b8 [2] f4 bf [2] e8 90 }

  condition:
    any of them
}