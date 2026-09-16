rule TTP_XOR_MULT_DOSStub_2ccf {
  strings:
    $key_2ccf = { 78 a7 [2] 0c bf [2] 4b bd [2] 0c ac [2] 42 a0 [2] 4e aa [2] 59 a1 [2] 42 ef [2] 7f }

  condition:
    any of them
}