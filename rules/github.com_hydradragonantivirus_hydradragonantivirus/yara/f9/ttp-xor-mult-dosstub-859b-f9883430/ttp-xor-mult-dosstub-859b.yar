rule TTP_XOR_MULT_DOSStub_859b {
  strings:
    $key_859b = { d1 f3 [2] a5 eb [2] e2 e9 [2] a5 f8 [2] eb f4 [2] e7 fe [2] f0 f5 [2] eb bb [2] d6 }

  condition:
    any of them
}