rule TTP_XOR_MULT_DOSStub_b19d {
  strings:
    $key_b19d = { e5 f5 [2] 91 ed [2] d6 ef [2] 91 fe [2] df f2 [2] d3 f8 [2] c4 f3 [2] df bd [2] e2 }

  condition:
    any of them
}