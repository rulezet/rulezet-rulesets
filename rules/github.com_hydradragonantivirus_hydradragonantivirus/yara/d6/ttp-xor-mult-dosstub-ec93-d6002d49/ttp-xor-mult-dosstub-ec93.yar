rule TTP_XOR_MULT_DOSStub_ec93 {
  strings:
    $key_ec93 = { b8 fb [2] cc e3 [2] 8b e1 [2] cc f0 [2] 82 fc [2] 8e f6 [2] 99 fd [2] 82 b3 [2] bf }

  condition:
    any of them
}