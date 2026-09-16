rule TTP_XOR_MULT_DOSStub_383a {
  strings:
    $key_383a = { 6c 52 [2] 18 4a [2] 5f 48 [2] 18 59 [2] 56 55 [2] 5a 5f [2] 4d 54 [2] 56 1a [2] 6b }

  condition:
    any of them
}