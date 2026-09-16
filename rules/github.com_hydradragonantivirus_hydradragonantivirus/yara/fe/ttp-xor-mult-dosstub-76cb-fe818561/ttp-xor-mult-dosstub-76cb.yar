rule TTP_XOR_MULT_DOSStub_76cb {
  strings:
    $key_76cb = { 22 a3 [2] 56 bb [2] 11 b9 [2] 56 a8 [2] 18 a4 [2] 14 ae [2] 03 a5 [2] 18 eb [2] 25 }

  condition:
    any of them
}