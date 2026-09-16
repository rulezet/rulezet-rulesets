rule TTP_XOR_QUAD_CurrentVersionRun_e1a9 {
  strings:
    $key_e1a9 = { b2 c6 [2] 96 c8 [2] bd e4 [2] 93 c6 [2] 87 dd [2] 88 c7 [2] 96 da [2] 94 db [2] 8f dd [2] 93 da [2] 8f f5 }

  condition:
    any of them
}