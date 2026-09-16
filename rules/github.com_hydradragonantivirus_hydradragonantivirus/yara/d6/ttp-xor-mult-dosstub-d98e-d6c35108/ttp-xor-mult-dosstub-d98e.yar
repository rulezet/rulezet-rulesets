rule TTP_XOR_MULT_DOSStub_d98e {
  strings:
    $key_d98e = { 8d e6 [2] f9 fe [2] be fc [2] f9 ed [2] b7 e1 [2] bb eb [2] ac e0 [2] b7 ae [2] 8a }

  condition:
    any of them
}