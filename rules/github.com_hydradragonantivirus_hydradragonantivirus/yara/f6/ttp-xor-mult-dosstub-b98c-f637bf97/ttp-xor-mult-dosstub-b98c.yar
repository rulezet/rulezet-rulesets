rule TTP_XOR_MULT_DOSStub_b98c {
  strings:
    $key_b98c = { ed e4 [2] 99 fc [2] de fe [2] 99 ef [2] d7 e3 [2] db e9 [2] cc e2 [2] d7 ac [2] ea }

  condition:
    any of them
}