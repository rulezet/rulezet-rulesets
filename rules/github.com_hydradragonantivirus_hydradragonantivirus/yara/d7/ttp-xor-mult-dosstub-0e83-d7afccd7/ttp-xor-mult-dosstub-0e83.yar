rule TTP_XOR_MULT_DOSStub_0e83 {
  strings:
    $key_0e83 = { 5a eb [2] 2e f3 [2] 69 f1 [2] 2e e0 [2] 60 ec [2] 6c e6 [2] 7b ed [2] 60 a3 [2] 5d }

  condition:
    any of them
}