rule TTP_XOR_QUAD_CurrentVersionRun_98d4 {
  strings:
    $key_98d4 = { cb bb [2] ef b5 [2] c4 99 [2] ea bb [2] fe a0 [2] f1 ba [2] ef a7 [2] ed a6 [2] f6 a0 [2] ea a7 [2] f6 88 }

  condition:
    any of them
}