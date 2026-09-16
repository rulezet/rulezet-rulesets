rule TTP_XOR_QUAD_CurrentVersionRun_26cc {
  strings:
    $key_26cc = { 75 a3 [2] 51 ad [2] 7a 81 [2] 54 a3 [2] 40 b8 [2] 4f a2 [2] 51 bf [2] 53 be [2] 48 b8 [2] 54 bf [2] 48 90 }

  condition:
    any of them
}