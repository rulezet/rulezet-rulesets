rule TTP_XOR_QUAD_CurrentVersionRun_9ac7 {
  strings:
    $key_9ac7 = { c9 a8 [2] ed a6 [2] c6 8a [2] e8 a8 [2] fc b3 [2] f3 a9 [2] ed b4 [2] ef b5 [2] f4 b3 [2] e8 b4 [2] f4 9b }

  condition:
    any of them
}