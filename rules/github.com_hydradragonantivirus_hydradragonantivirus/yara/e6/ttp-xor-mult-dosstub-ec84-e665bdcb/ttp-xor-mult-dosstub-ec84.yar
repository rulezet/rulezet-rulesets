rule TTP_XOR_MULT_DOSStub_ec84 {
  strings:
    $key_ec84 = { b8 ec [2] cc f4 [2] 8b f6 [2] cc e7 [2] 82 eb [2] 8e e1 [2] 99 ea [2] 82 a4 [2] bf }

  condition:
    any of them
}