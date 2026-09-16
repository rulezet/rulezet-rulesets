rule TTP_XOR_QUAD_CurrentVersionRun_98db {
  strings:
    $key_98db = { cb b4 [2] ef ba [2] c4 96 [2] ea b4 [2] fe af [2] f1 b5 [2] ef a8 [2] ed a9 [2] f6 af [2] ea a8 [2] f6 87 }

  condition:
    any of them
}