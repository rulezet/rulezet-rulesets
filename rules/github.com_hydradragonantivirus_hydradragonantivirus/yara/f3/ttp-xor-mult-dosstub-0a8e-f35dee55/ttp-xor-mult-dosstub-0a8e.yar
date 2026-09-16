rule TTP_XOR_MULT_DOSStub_0a8e {
  strings:
    $key_0a8e = { 5e e6 [2] 2a fe [2] 6d fc [2] 2a ed [2] 64 e1 [2] 68 eb [2] 7f e0 [2] 64 ae [2] 59 }

  condition:
    any of them
}