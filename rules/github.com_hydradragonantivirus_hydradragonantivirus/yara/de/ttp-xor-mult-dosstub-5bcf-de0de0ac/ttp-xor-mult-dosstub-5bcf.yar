rule TTP_XOR_MULT_DOSStub_5bcf {
  strings:
    $key_5bcf = { 0f a7 [2] 7b bf [2] 3c bd [2] 7b ac [2] 35 a0 [2] 39 aa [2] 2e a1 [2] 35 ef [2] 08 }

  condition:
    any of them
}