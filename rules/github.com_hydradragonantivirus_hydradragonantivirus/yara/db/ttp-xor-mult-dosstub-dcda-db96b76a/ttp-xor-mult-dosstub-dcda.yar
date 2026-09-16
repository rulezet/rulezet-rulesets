rule TTP_XOR_MULT_DOSStub_dcda {
  strings:
    $key_dcda = { 88 b2 [2] fc aa [2] bb a8 [2] fc b9 [2] b2 b5 [2] be bf [2] a9 b4 [2] b2 fa [2] 8f }

  condition:
    any of them
}