rule TTP_XOR_QUAD_CurrentVersionRun_a0cc {
  strings:
    $key_a0cc = { f3 a3 [2] d7 ad [2] fc 81 [2] d2 a3 [2] c6 b8 [2] c9 a2 [2] d7 bf [2] d5 be [2] ce b8 [2] d2 bf [2] ce 90 }

  condition:
    any of them
}