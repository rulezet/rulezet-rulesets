rule TTP_XOR_MULT_DOSStub_f782 {
  strings:
    $key_f782 = { a3 ea [2] d7 f2 [2] 90 f0 [2] d7 e1 [2] 99 ed [2] 95 e7 [2] 82 ec [2] 99 a2 [2] a4 }

  condition:
    any of them
}