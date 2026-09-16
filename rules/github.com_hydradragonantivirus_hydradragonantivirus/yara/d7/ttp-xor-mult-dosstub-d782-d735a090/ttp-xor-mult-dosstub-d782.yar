rule TTP_XOR_MULT_DOSStub_d782 {
  strings:
    $key_d782 = { 83 ea [2] f7 f2 [2] b0 f0 [2] f7 e1 [2] b9 ed [2] b5 e7 [2] a2 ec [2] b9 a2 [2] 84 }

  condition:
    any of them
}