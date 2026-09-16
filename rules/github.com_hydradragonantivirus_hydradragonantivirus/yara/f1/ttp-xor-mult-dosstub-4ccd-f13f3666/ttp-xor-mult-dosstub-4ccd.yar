rule TTP_XOR_MULT_DOSStub_4ccd {
  strings:
    $key_4ccd = { 18 a5 [2] 6c bd [2] 2b bf [2] 6c ae [2] 22 a2 [2] 2e a8 [2] 39 a3 [2] 22 ed [2] 1f }

  condition:
    any of them
}