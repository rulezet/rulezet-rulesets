rule TTP_XOR_MULT_DOSStub_2dcf {
  strings:
    $key_2dcf = { 79 a7 [2] 0d bf [2] 4a bd [2] 0d ac [2] 43 a0 [2] 4f aa [2] 58 a1 [2] 43 ef [2] 7e }

  condition:
    any of them
}