rule TTP_XOR_MULT_DOSStub_db8e {
  strings:
    $key_db8e = { 8f e6 [2] fb fe [2] bc fc [2] fb ed [2] b5 e1 [2] b9 eb [2] ae e0 [2] b5 ae [2] 88 }

  condition:
    any of them
}