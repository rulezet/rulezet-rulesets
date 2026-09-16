rule TTP_XOR_MULT_DOSStub_c9c5 {
  strings:
    $key_c9c5 = { 9d ad [2] e9 b5 [2] ae b7 [2] e9 a6 [2] a7 aa [2] ab a0 [2] bc ab [2] a7 e5 [2] 9a }

  condition:
    any of them
}