rule TTP_XOR_MULT_DOSStub_675a {
  strings:
    $key_675a = { 33 32 [2] 47 2a [2] 00 28 [2] 47 39 [2] 09 35 [2] 05 3f [2] 12 34 [2] 09 7a [2] 34 }

  condition:
    any of them
}