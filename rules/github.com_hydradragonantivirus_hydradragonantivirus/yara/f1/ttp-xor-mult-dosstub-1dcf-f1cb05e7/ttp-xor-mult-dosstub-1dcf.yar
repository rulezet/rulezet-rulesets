rule TTP_XOR_MULT_DOSStub_1dcf {
  strings:
    $key_1dcf = { 49 a7 [2] 3d bf [2] 7a bd [2] 3d ac [2] 73 a0 [2] 7f aa [2] 68 a1 [2] 73 ef [2] 4e }

  condition:
    any of them
}