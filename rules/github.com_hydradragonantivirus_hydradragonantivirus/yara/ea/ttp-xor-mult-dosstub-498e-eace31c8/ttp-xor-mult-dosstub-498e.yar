rule TTP_XOR_MULT_DOSStub_498e {
  strings:
    $key_498e = { 1d e6 [2] 69 fe [2] 2e fc [2] 69 ed [2] 27 e1 [2] 2b eb [2] 3c e0 [2] 27 ae [2] 1a }

  condition:
    any of them
}