rule TTP_XOR_QUAD_CurrentVersionRun_e1d0 {
  strings:
    $key_e1d0 = { b2 bf [2] 96 b1 [2] bd 9d [2] 93 bf [2] 87 a4 [2] 88 be [2] 96 a3 [2] 94 a2 [2] 8f a4 [2] 93 a3 [2] 8f 8c }

  condition:
    any of them
}