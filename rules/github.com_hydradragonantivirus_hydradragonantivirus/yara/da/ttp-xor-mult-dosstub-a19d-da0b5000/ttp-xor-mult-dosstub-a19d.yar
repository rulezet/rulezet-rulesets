rule TTP_XOR_MULT_DOSStub_a19d {
  strings:
    $key_a19d = { f5 f5 [2] 81 ed [2] c6 ef [2] 81 fe [2] cf f2 [2] c3 f8 [2] d4 f3 [2] cf bd [2] f2 }

  condition:
    any of them
}