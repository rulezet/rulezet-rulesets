rule TTP_XOR_MULT_DOSStub_765a {
  strings:
    $key_765a = { 22 32 [2] 56 2a [2] 11 28 [2] 56 39 [2] 18 35 [2] 14 3f [2] 03 34 [2] 18 7a [2] 25 }

  condition:
    any of them
}