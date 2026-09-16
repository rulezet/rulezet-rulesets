rule TTP_XOR_MULT_DOSStub_ec8c {
  strings:
    $key_ec8c = { b8 e4 [2] cc fc [2] 8b fe [2] cc ef [2] 82 e3 [2] 8e e9 [2] 99 e2 [2] 82 ac [2] bf }

  condition:
    any of them
}