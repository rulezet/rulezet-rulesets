rule TTP_XOR_QUAD_CurrentVersionRun_98c0 {
  strings:
    $key_98c0 = { cb af [2] ef a1 [2] c4 8d [2] ea af [2] fe b4 [2] f1 ae [2] ef b3 [2] ed b2 [2] f6 b4 [2] ea b3 [2] f6 9c }

  condition:
    any of them
}