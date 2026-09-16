rule TTP_XOR_QUAD_CurrentVersionRun_c6cc {
  strings:
    $key_c6cc = { 95 a3 [2] b1 ad [2] 9a 81 [2] b4 a3 [2] a0 b8 [2] af a2 [2] b1 bf [2] b3 be [2] a8 b8 [2] b4 bf [2] a8 90 }

  condition:
    any of them
}