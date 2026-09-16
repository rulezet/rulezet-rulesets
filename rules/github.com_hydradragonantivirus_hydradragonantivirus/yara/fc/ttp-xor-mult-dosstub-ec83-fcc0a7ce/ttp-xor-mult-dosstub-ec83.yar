rule TTP_XOR_MULT_DOSStub_ec83 {
  strings:
    $key_ec83 = { b8 eb [2] cc f3 [2] 8b f1 [2] cc e0 [2] 82 ec [2] 8e e6 [2] 99 ed [2] 82 a3 [2] bf }

  condition:
    any of them
}