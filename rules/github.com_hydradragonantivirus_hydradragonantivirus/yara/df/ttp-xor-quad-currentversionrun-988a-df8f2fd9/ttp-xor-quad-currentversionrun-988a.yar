rule TTP_XOR_QUAD_CurrentVersionRun_988a {
  strings:
    $key_988a = { cb e5 [2] ef eb [2] c4 c7 [2] ea e5 [2] fe fe [2] f1 e4 [2] ef f9 [2] ed f8 [2] f6 fe [2] ea f9 [2] f6 d6 }

  condition:
    any of them
}