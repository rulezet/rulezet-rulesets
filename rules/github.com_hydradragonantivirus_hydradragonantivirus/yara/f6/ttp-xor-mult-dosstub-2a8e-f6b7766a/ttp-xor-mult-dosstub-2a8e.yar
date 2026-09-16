rule TTP_XOR_MULT_DOSStub_2a8e {
  strings:
    $key_2a8e = { 7e e6 [2] 0a fe [2] 4d fc [2] 0a ed [2] 44 e1 [2] 48 eb [2] 5f e0 [2] 44 ae [2] 79 }

  condition:
    any of them
}