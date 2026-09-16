rule TTP_XOR_MULT_DOSStub_8ccf {
  strings:
    $key_8ccf = { d8 a7 [2] ac bf [2] eb bd [2] ac ac [2] e2 a0 [2] ee aa [2] f9 a1 [2] e2 ef [2] df }

  condition:
    any of them
}