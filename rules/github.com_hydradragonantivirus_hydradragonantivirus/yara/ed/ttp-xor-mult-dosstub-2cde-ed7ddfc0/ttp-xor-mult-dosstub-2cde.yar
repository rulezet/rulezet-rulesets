rule TTP_XOR_MULT_DOSStub_2cde {
  strings:
    $key_2cde = { 78 b6 [2] 0c ae [2] 4b ac [2] 0c bd [2] 42 b1 [2] 4e bb [2] 59 b0 [2] 42 fe [2] 7f }

  condition:
    any of them
}