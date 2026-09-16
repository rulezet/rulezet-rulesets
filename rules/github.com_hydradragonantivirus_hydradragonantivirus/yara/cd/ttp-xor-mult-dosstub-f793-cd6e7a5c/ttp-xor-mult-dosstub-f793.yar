rule TTP_XOR_MULT_DOSStub_f793 {
  strings:
    $key_f793 = { a3 fb [2] d7 e3 [2] 90 e1 [2] d7 f0 [2] 99 fc [2] 95 f6 [2] 82 fd [2] 99 b3 [2] a4 }

  condition:
    any of them
}