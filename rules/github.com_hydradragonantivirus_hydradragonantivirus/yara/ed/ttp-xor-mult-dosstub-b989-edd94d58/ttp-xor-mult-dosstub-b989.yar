rule TTP_XOR_MULT_DOSStub_b989 {
  strings:
    $key_b989 = { ed e1 [2] 99 f9 [2] de fb [2] 99 ea [2] d7 e6 [2] db ec [2] cc e7 [2] d7 a9 [2] ea }

  condition:
    any of them
}