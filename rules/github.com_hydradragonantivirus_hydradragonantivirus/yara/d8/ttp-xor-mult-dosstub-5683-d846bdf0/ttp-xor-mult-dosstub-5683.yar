rule TTP_XOR_MULT_DOSStub_5683 {
  strings:
    $key_5683 = { 02 eb [2] 76 f3 [2] 31 f1 [2] 76 e0 [2] 38 ec [2] 34 e6 [2] 23 ed [2] 38 a3 [2] 05 }

  condition:
    any of them
}