rule TTP_XOR_QUAD_CurrentVersionRun_988c {
  strings:
    $key_988c = { cb e3 [2] ef ed [2] c4 c1 [2] ea e3 [2] fe f8 [2] f1 e2 [2] ef ff [2] ed fe [2] f6 f8 [2] ea ff [2] f6 d0 }

  condition:
    any of them
}