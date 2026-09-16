rule TTP_XOR_MULT_DOSStub_c9da {
  strings:
    $key_c9da = { 9d b2 [2] e9 aa [2] ae a8 [2] e9 b9 [2] a7 b5 [2] ab bf [2] bc b4 [2] a7 fa [2] 9a }

  condition:
    any of them
}