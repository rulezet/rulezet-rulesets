rule TTP_XOR_MULT_DOSStub_7ccf {
  strings:
    $key_7ccf = { 28 a7 [2] 5c bf [2] 1b bd [2] 5c ac [2] 12 a0 [2] 1e aa [2] 09 a1 [2] 12 ef [2] 2f }

  condition:
    any of them
}