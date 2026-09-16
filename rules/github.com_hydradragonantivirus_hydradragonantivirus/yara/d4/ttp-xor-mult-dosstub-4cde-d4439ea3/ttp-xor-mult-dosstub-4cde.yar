rule TTP_XOR_MULT_DOSStub_4cde {
  strings:
    $key_4cde = { 18 b6 [2] 6c ae [2] 2b ac [2] 6c bd [2] 22 b1 [2] 2e bb [2] 39 b0 [2] 22 fe [2] 1f }

  condition:
    any of them
}