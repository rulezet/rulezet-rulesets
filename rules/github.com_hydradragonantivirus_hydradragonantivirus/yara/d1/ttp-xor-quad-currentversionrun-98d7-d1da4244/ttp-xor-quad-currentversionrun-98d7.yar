rule TTP_XOR_QUAD_CurrentVersionRun_98d7 {
  strings:
    $key_98d7 = { cb b8 [2] ef b6 [2] c4 9a [2] ea b8 [2] fe a3 [2] f1 b9 [2] ef a4 [2] ed a5 [2] f6 a3 [2] ea a4 [2] f6 8b }

  condition:
    any of them
}