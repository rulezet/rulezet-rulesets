rule TTP_XOR_MULT_DOSStub_53c2 {
  strings:
    $key_53c2 = { 07 aa [2] 73 b2 [2] 34 b0 [2] 73 a1 [2] 3d ad [2] 31 a7 [2] 26 ac [2] 3d e2 [2] 00 }

  condition:
    any of them
}