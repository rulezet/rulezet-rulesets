rule TTP_XOR_MULT_DOSStub_7f35 {
  strings:
    $key_7f35 = { 2b 5d [2] 5f 45 [2] 18 47 [2] 5f 56 [2] 11 5a [2] 1d 50 [2] 0a 5b [2] 11 15 [2] 2c }

  condition:
    any of them
}