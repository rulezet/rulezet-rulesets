rule TTP_XOR_MULT_DOSStub_1a5a {
  strings:
    $key_1a5a = { 4e 32 [2] 3a 2a [2] 7d 28 [2] 3a 39 [2] 74 35 [2] 78 3f [2] 6f 34 [2] 74 7a [2] 49 }

  condition:
    any of them
}