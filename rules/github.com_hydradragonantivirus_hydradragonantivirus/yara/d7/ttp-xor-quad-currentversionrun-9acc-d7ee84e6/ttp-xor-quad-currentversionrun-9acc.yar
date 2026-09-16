rule TTP_XOR_QUAD_CurrentVersionRun_9acc {
  strings:
    $key_9acc = { c9 a3 [2] ed ad [2] c6 81 [2] e8 a3 [2] fc b8 [2] f3 a2 [2] ed bf [2] ef be [2] f4 b8 [2] e8 bf [2] f4 90 }

  condition:
    any of them
}