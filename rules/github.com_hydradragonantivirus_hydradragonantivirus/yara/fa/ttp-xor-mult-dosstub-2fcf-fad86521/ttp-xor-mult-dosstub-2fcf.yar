rule TTP_XOR_MULT_DOSStub_2fcf {
  strings:
    $key_2fcf = { 7b a7 [2] 0f bf [2] 48 bd [2] 0f ac [2] 41 a0 [2] 4d aa [2] 5a a1 [2] 41 ef [2] 7c }

  condition:
    any of them
}