rule TTP_XOR_MULT_DOSStub_0dcf {
  strings:
    $key_0dcf = { 59 a7 [2] 2d bf [2] 6a bd [2] 2d ac [2] 63 a0 [2] 6f aa [2] 78 a1 [2] 63 ef [2] 5e }

  condition:
    any of them
}