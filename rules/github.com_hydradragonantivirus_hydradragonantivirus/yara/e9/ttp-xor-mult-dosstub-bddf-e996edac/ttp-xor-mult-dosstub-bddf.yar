rule TTP_XOR_MULT_DOSStub_bddf {
  strings:
    $key_bddf = { e9 b7 [2] 9d af [2] da ad [2] 9d bc [2] d3 b0 [2] df ba [2] c8 b1 [2] d3 ff [2] ee }

  condition:
    any of them
}