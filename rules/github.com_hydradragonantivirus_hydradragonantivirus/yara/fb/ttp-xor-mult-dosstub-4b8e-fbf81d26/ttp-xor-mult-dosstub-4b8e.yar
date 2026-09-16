rule TTP_XOR_MULT_DOSStub_4b8e {
  strings:
    $key_4b8e = { 1f e6 [2] 6b fe [2] 2c fc [2] 6b ed [2] 25 e1 [2] 29 eb [2] 3e e0 [2] 25 ae [2] 18 }

  condition:
    any of them
}