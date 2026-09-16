rule TTP_XOR_MULT_DOSStub_8bcf {
  strings:
    $key_8bcf = { df a7 [2] ab bf [2] ec bd [2] ab ac [2] e5 a0 [2] e9 aa [2] fe a1 [2] e5 ef [2] d8 }

  condition:
    any of them
}