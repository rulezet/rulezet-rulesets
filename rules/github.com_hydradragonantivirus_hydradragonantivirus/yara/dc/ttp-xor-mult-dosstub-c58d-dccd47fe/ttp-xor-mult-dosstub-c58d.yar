rule TTP_XOR_MULT_DOSStub_c58d {
  strings:
    $key_c58d = { 91 e5 [2] e5 fd [2] a2 ff [2] e5 ee [2] ab e2 [2] a7 e8 [2] b0 e3 [2] ab ad [2] 96 }

  condition:
    any of them
}