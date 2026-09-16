rule TTP_XOR_MULT_DOSStub_d983 {
  strings:
    $key_d983 = { 8d eb [2] f9 f3 [2] be f1 [2] f9 e0 [2] b7 ec [2] bb e6 [2] ac ed [2] b7 a3 [2] 8a }

  condition:
    any of them
}