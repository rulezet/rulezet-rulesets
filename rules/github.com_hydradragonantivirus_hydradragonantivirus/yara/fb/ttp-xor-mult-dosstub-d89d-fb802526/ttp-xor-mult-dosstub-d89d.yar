rule TTP_XOR_MULT_DOSStub_d89d {
  strings:
    $key_d89d = { 8c f5 [2] f8 ed [2] bf ef [2] f8 fe [2] b6 f2 [2] ba f8 [2] ad f3 [2] b6 bd [2] 8b }

  condition:
    any of them
}