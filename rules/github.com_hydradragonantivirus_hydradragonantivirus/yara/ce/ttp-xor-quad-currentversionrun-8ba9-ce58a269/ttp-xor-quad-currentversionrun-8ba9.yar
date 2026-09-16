rule TTP_XOR_QUAD_CurrentVersionRun_8ba9 {
  strings:
    $key_8ba9 = { d8 c6 [2] fc c8 [2] d7 e4 [2] f9 c6 [2] ed dd [2] e2 c7 [2] fc da [2] fe db [2] e5 dd [2] f9 da [2] e5 f5 }

  condition:
    any of them
}