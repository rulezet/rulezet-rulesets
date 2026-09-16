rule TTP_XOR_MULT_DOSStub_90dd {
  strings:
    $key_90dd = { c4 b5 [2] b0 ad [2] f7 af [2] b0 be [2] fe b2 [2] f2 b8 [2] e5 b3 [2] fe fd [2] c3 }

  condition:
    any of them
}