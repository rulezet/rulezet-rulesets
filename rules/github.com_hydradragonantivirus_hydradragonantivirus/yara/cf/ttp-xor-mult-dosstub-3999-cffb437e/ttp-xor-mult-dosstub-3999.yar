rule TTP_XOR_MULT_DOSStub_3999 {
  strings:
    $key_3999 = { 6d f1 [2] 19 e9 [2] 5e eb [2] 19 fa [2] 57 f6 [2] 5b fc [2] 4c f7 [2] 57 b9 [2] 6a }

  condition:
    any of them
}