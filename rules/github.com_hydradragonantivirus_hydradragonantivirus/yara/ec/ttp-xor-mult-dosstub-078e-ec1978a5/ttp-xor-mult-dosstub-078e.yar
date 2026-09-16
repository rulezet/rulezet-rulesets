rule TTP_XOR_MULT_DOSStub_078e {
  strings:
    $key_078e = { 53 e6 [2] 27 fe [2] 60 fc [2] 27 ed [2] 69 e1 [2] 65 eb [2] 72 e0 [2] 69 ae [2] 54 }

  condition:
    any of them
}