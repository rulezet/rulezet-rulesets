rule TTP_XOR_MULT_DOSStub_038e {
  strings:
    $key_038e = { 57 e6 [2] 23 fe [2] 64 fc [2] 23 ed [2] 6d e1 [2] 61 eb [2] 76 e0 [2] 6d ae [2] 50 }

  condition:
    any of them
}