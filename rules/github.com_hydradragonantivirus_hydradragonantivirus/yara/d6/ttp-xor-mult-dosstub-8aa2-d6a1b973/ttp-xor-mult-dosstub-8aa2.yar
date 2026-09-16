rule TTP_XOR_MULT_DOSStub_8aa2 {
  strings:
    $key_8aa2 = { de ca [2] aa d2 [2] ed d0 [2] aa c1 [2] e4 cd [2] e8 c7 [2] ff cc [2] e4 82 [2] d9 }

  condition:
    any of them
}