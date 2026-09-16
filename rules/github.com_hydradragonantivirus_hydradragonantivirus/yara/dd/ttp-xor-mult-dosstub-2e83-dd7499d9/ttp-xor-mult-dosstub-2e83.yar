rule TTP_XOR_MULT_DOSStub_2e83 {
  strings:
    $key_2e83 = { 7a eb [2] 0e f3 [2] 49 f1 [2] 0e e0 [2] 40 ec [2] 4c e6 [2] 5b ed [2] 40 a3 [2] 7d }

  condition:
    any of them
}