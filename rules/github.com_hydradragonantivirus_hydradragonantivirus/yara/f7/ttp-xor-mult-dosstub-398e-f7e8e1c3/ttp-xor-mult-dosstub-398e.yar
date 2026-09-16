rule TTP_XOR_MULT_DOSStub_398e {
  strings:
    $key_398e = { 6d e6 [2] 19 fe [2] 5e fc [2] 19 ed [2] 57 e1 [2] 5b eb [2] 4c e0 [2] 57 ae [2] 6a }

  condition:
    any of them
}