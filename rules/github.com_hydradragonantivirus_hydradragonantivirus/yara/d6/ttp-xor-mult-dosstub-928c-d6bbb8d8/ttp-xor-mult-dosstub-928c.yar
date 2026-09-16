rule TTP_XOR_MULT_DOSStub_928c {
  strings:
    $key_928c = { c6 e4 [2] b2 fc [2] f5 fe [2] b2 ef [2] fc e3 [2] f0 e9 [2] e7 e2 [2] fc ac [2] c1 }

  condition:
    any of them
}