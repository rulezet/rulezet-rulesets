rule TTP_XOR_QUAD_CurrentVersionRun_c7cc {
  strings:
    $key_c7cc = { 94 a3 [2] b0 ad [2] 9b 81 [2] b5 a3 [2] a1 b8 [2] ae a2 [2] b0 bf [2] b2 be [2] a9 b8 [2] b5 bf [2] a9 90 }

  condition:
    any of them
}