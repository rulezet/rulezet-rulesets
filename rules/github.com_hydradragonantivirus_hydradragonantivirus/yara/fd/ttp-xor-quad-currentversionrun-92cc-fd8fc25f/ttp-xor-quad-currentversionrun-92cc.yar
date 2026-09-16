rule TTP_XOR_QUAD_CurrentVersionRun_92cc {
  strings:
    $key_92cc = { c1 a3 [2] e5 ad [2] ce 81 [2] e0 a3 [2] f4 b8 [2] fb a2 [2] e5 bf [2] e7 be [2] fc b8 [2] e0 bf [2] fc 90 }

  condition:
    any of them
}