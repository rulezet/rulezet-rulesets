rule TTP_XOR_QUAD_CurrentVersionRun_e5cc {
  strings:
    $key_e5cc = { b6 a3 [2] 92 ad [2] b9 81 [2] 97 a3 [2] 83 b8 [2] 8c a2 [2] 92 bf [2] 90 be [2] 8b b8 [2] 97 bf [2] 8b 90 }

  condition:
    any of them
}