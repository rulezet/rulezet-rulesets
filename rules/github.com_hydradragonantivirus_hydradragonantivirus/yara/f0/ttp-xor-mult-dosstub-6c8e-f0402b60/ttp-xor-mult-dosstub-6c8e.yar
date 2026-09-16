rule TTP_XOR_MULT_DOSStub_6c8e {
  strings:
    $key_6c8e = { 38 e6 [2] 4c fe [2] 0b fc [2] 4c ed [2] 02 e1 [2] 0e eb [2] 19 e0 [2] 02 ae [2] 3f }

  condition:
    any of them
}