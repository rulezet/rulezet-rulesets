rule TTP_XOR_MULT_DOSStub_ca8a {
  strings:
    $key_ca8a = { 9e e2 [2] ea fa [2] ad f8 [2] ea e9 [2] a4 e5 [2] a8 ef [2] bf e4 [2] a4 aa [2] 99 }

  condition:
    any of them
}