rule TTP_XOR_QUAD_CurrentVersionRun_d0cc {
  strings:
    $key_d0cc = { 83 a3 [2] a7 ad [2] 8c 81 [2] a2 a3 [2] b6 b8 [2] b9 a2 [2] a7 bf [2] a5 be [2] be b8 [2] a2 bf [2] be 90 }

  condition:
    any of them
}