rule TTP_XOR_MULT_DOSStub_c98e {
  strings:
    $key_c98e = { 9d e6 [2] e9 fe [2] ae fc [2] e9 ed [2] a7 e1 [2] ab eb [2] bc e0 [2] a7 ae [2] 9a }

  condition:
    any of them
}