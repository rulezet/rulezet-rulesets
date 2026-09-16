rule TTP_XOR_MULT_DOSStub_fbdd {
  strings:
    $key_fbdd = { af b5 [2] db ad [2] 9c af [2] db be [2] 95 b2 [2] 99 b8 [2] 8e b3 [2] 95 fd [2] a8 }

  condition:
    any of them
}