rule TTP_XOR_MULT_DOSStub_4dcb {
  strings:
    $key_4dcb = { 19 a3 [2] 6d bb [2] 2a b9 [2] 6d a8 [2] 23 a4 [2] 2f ae [2] 38 a5 [2] 23 eb [2] 1e }

  condition:
    any of them
}