rule TTP_XOR_MULT_DOSStub_e783 {
  strings:
    $key_e783 = { b3 eb [2] c7 f3 [2] 80 f1 [2] c7 e0 [2] 89 ec [2] 85 e6 [2] 92 ed [2] 89 a3 [2] b4 }

  condition:
    any of them
}