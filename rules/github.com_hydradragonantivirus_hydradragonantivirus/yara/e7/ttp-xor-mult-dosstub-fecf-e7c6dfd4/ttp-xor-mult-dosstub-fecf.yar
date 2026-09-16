rule TTP_XOR_MULT_DOSStub_fecf {
  strings:
    $key_fecf = { aa a7 [2] de bf [2] 99 bd [2] de ac [2] 90 a0 [2] 9c aa [2] 8b a1 [2] 90 ef [2] ad }

  condition:
    any of them
}