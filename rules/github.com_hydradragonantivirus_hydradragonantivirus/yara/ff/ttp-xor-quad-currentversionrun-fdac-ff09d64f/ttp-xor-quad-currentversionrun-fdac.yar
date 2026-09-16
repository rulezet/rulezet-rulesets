rule TTP_XOR_QUAD_CurrentVersionRun_fdac {
  strings:
    $key_fdac = { ae c3 [2] 8a cd [2] a1 e1 [2] 8f c3 [2] 9b d8 [2] 94 c2 [2] 8a df [2] 88 de [2] 93 d8 [2] 8f df [2] 93 f0 }

  condition:
    any of them
}