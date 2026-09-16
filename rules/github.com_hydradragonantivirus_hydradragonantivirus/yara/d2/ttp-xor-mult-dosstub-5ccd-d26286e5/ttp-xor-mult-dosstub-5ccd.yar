rule TTP_XOR_MULT_DOSStub_5ccd {
  strings:
    $key_5ccd = { 08 a5 [2] 7c bd [2] 3b bf [2] 7c ae [2] 32 a2 [2] 3e a8 [2] 29 a3 [2] 32 ed [2] 0f }

  condition:
    any of them
}