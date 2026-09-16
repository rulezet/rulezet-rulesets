rule TTP_XOR_MULT_DOSStub_3dcb {
  strings:
    $key_3dcb = { 69 a3 [2] 1d bb [2] 5a b9 [2] 1d a8 [2] 53 a4 [2] 5f ae [2] 48 a5 [2] 53 eb [2] 6e }

  condition:
    any of them
}