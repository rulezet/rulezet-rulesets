rule TTP_XOR_QUAD_CurrentVersionRun_77cc {
  strings:
    $key_77cc = { 24 a3 [2] 00 ad [2] 2b 81 [2] 05 a3 [2] 11 b8 [2] 1e a2 [2] 00 bf [2] 02 be [2] 19 b8 [2] 05 bf [2] 19 90 }

  condition:
    any of them
}