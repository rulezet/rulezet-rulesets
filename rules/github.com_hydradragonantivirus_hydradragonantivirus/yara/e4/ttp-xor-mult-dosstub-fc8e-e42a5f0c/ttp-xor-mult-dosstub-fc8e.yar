rule TTP_XOR_MULT_DOSStub_fc8e {
  strings:
    $key_fc8e = { a8 e6 [2] dc fe [2] 9b fc [2] dc ed [2] 92 e1 [2] 9e eb [2] 89 e0 [2] 92 ae [2] af }

  condition:
    any of them
}