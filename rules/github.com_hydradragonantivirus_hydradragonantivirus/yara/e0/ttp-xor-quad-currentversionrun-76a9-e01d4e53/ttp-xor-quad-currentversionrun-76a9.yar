rule TTP_XOR_QUAD_CurrentVersionRun_76a9 {
  strings:
    $key_76a9 = { 25 c6 [2] 01 c8 [2] 2a e4 [2] 04 c6 [2] 10 dd [2] 1f c7 [2] 01 da [2] 03 db [2] 18 dd [2] 04 da [2] 18 f5 }

  condition:
    any of them
}