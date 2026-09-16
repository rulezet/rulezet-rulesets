rule TTP_XOR_MULT_DOSStub_c79d {
  strings:
    $key_c79d = { 93 f5 [2] e7 ed [2] a0 ef [2] e7 fe [2] a9 f2 [2] a5 f8 [2] b2 f3 [2] a9 bd [2] 94 }

  condition:
    any of them
}