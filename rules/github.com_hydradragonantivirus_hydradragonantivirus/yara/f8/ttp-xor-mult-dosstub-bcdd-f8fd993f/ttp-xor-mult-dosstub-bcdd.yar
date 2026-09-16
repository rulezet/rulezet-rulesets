rule TTP_XOR_MULT_DOSStub_bcdd {
  strings:
    $key_bcdd = { e8 b5 [2] 9c ad [2] db af [2] 9c be [2] d2 b2 [2] de b8 [2] c9 b3 [2] d2 fd [2] ef }

  condition:
    any of them
}