rule TTP_XOR_MULT_DOSStub_338e {
  strings:
    $key_338e = { 67 e6 [2] 13 fe [2] 54 fc [2] 13 ed [2] 5d e1 [2] 51 eb [2] 46 e0 [2] 5d ae [2] 60 }

  condition:
    any of them
}