rule TTP_XOR_MULT_DOSStub_cccf {
  strings:
    $key_cccf = { 98 a7 [2] ec bf [2] ab bd [2] ec ac [2] a2 a0 [2] ae aa [2] b9 a1 [2] a2 ef [2] 9f }

  condition:
    any of them
}