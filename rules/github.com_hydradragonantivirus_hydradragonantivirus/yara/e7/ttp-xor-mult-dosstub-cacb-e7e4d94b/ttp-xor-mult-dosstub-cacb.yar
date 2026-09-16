rule TTP_XOR_MULT_DOSStub_cacb {
  strings:
    $key_cacb = { 9e a3 [2] ea bb [2] ad b9 [2] ea a8 [2] a4 a4 [2] a8 ae [2] bf a5 [2] a4 eb [2] 99 }

  condition:
    any of them
}