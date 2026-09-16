rule TTP_XOR_MULT_DOSStub_0ccd {
  strings:
    $key_0ccd = { 58 a5 [2] 2c bd [2] 6b bf [2] 2c ae [2] 62 a2 [2] 6e a8 [2] 79 a3 [2] 62 ed [2] 5f }

  condition:
    any of them
}