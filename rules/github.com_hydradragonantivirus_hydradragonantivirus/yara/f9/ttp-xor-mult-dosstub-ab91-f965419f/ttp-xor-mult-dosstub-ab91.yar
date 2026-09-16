rule TTP_XOR_MULT_DOSStub_ab91 {
  strings:
    $key_ab91 = { ff f9 [2] 8b e1 [2] cc e3 [2] 8b f2 [2] c5 fe [2] c9 f4 [2] de ff [2] c5 b1 [2] f8 }

  condition:
    any of them
}