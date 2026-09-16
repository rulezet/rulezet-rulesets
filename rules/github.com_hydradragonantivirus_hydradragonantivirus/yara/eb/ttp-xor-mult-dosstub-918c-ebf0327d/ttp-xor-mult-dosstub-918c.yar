rule TTP_XOR_MULT_DOSStub_918c {
  strings:
    $key_918c = { c5 e4 [2] b1 fc [2] f6 fe [2] b1 ef [2] ff e3 [2] f3 e9 [2] e4 e2 [2] ff ac [2] c2 }

  condition:
    any of them
}