rule TTP_XOR_QUAD_CurrentVersionRun_e1d1 {
  strings:
    $key_e1d1 = { b2 be [2] 96 b0 [2] bd 9c [2] 93 be [2] 87 a5 [2] 88 bf [2] 96 a2 [2] 94 a3 [2] 8f a5 [2] 93 a2 [2] 8f 8d }

  condition:
    any of them
}