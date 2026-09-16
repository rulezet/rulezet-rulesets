rule TTP_XOR_MULT_DOSStub_b98e {
  strings:
    $key_b98e = { ed e6 [2] 99 fe [2] de fc [2] 99 ed [2] d7 e1 [2] db eb [2] cc e0 [2] d7 ae [2] ea }

  condition:
    any of them
}