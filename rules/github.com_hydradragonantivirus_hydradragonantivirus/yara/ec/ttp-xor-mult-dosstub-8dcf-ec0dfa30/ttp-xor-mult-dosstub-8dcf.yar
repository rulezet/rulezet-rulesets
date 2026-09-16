rule TTP_XOR_MULT_DOSStub_8dcf {
  strings:
    $key_8dcf = { d9 a7 [2] ad bf [2] ea bd [2] ad ac [2] e3 a0 [2] ef aa [2] f8 a1 [2] e3 ef [2] de }

  condition:
    any of them
}