rule TTP_XOR_MULT_DOSStub_b09d {
  strings:
    $key_b09d = { e4 f5 [2] 90 ed [2] d7 ef [2] 90 fe [2] de f2 [2] d2 f8 [2] c5 f3 [2] de bd [2] e3 }

  condition:
    any of them
}