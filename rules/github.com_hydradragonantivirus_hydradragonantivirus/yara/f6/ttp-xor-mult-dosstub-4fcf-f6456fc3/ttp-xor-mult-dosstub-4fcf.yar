rule TTP_XOR_MULT_DOSStub_4fcf {
  strings:
    $key_4fcf = { 1b a7 [2] 6f bf [2] 28 bd [2] 6f ac [2] 21 a0 [2] 2d aa [2] 3a a1 [2] 21 ef [2] 1c }

  condition:
    any of them
}