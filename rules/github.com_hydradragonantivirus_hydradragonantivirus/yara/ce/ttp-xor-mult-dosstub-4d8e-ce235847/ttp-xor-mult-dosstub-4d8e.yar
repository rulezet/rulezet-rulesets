rule TTP_XOR_MULT_DOSStub_4d8e {
  strings:
    $key_4d8e = { 19 e6 [2] 6d fe [2] 2a fc [2] 6d ed [2] 23 e1 [2] 2f eb [2] 38 e0 [2] 23 ae [2] 1e }

  condition:
    any of them
}