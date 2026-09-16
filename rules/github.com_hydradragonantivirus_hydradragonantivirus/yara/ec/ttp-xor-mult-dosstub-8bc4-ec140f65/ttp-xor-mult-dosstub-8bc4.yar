rule TTP_XOR_MULT_DOSStub_8bc4 {
  strings:
    $key_8bc4 = { df ac [2] ab b4 [2] ec b6 [2] ab a7 [2] e5 ab [2] e9 a1 [2] fe aa [2] e5 e4 [2] d8 }

  condition:
    any of them
}