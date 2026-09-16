rule TTP_XOR_MULT_DOSStub_0d8e {
  strings:
    $key_0d8e = { 59 e6 [2] 2d fe [2] 6a fc [2] 2d ed [2] 63 e1 [2] 6f eb [2] 78 e0 [2] 63 ae [2] 5e }

  condition:
    any of them
}