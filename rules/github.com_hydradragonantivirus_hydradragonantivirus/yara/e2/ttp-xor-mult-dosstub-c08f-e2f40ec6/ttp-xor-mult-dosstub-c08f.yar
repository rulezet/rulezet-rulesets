rule TTP_XOR_MULT_DOSStub_c08f {
  strings:
    $key_c08f = { 94 e7 [2] e0 ff [2] a7 fd [2] e0 ec [2] ae e0 [2] a2 ea [2] b5 e1 [2] ae af [2] 93 }

  condition:
    any of them
}