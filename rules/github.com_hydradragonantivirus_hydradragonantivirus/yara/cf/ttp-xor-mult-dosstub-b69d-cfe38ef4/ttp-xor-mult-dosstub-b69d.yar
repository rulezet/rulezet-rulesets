rule TTP_XOR_MULT_DOSStub_b69d {
  strings:
    $key_b69d = { e2 f5 [2] 96 ed [2] d1 ef [2] 96 fe [2] d8 f2 [2] d4 f8 [2] c3 f3 [2] d8 bd [2] e5 }

  condition:
    any of them
}