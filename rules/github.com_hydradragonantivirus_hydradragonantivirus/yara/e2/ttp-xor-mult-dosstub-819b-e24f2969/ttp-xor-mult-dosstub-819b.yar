rule TTP_XOR_MULT_DOSStub_819b {
  strings:
    $key_819b = { d5 f3 [2] a1 eb [2] e6 e9 [2] a1 f8 [2] ef f4 [2] e3 fe [2] f4 f5 [2] ef bb [2] d2 }

  condition:
    any of them
}