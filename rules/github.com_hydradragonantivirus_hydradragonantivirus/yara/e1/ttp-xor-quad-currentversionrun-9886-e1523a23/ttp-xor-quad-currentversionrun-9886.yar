rule TTP_XOR_QUAD_CurrentVersionRun_9886 {
  strings:
    $key_9886 = { cb e9 [2] ef e7 [2] c4 cb [2] ea e9 [2] fe f2 [2] f1 e8 [2] ef f5 [2] ed f4 [2] f6 f2 [2] ea f5 [2] f6 da }

  condition:
    any of them
}