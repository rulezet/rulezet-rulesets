rule TTP_XOR_MULT_DOSStub_428e {
  strings:
    $key_428e = { 16 e6 [2] 62 fe [2] 25 fc [2] 62 ed [2] 2c e1 [2] 20 eb [2] 37 e0 [2] 2c ae [2] 11 }

  condition:
    any of them
}