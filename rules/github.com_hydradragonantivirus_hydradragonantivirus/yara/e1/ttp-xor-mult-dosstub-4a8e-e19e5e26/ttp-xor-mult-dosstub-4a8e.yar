rule TTP_XOR_MULT_DOSStub_4a8e {
  strings:
    $key_4a8e = { 1e e6 [2] 6a fe [2] 2d fc [2] 6a ed [2] 24 e1 [2] 28 eb [2] 3f e0 [2] 24 ae [2] 19 }

  condition:
    any of them
}