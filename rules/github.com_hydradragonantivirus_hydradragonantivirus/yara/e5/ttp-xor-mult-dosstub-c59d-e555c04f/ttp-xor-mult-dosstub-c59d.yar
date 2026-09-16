rule TTP_XOR_MULT_DOSStub_c59d {
  strings:
    $key_c59d = { 91 f5 [2] e5 ed [2] a2 ef [2] e5 fe [2] ab f2 [2] a7 f8 [2] b0 f3 [2] ab bd [2] 96 }

  condition:
    any of them
}