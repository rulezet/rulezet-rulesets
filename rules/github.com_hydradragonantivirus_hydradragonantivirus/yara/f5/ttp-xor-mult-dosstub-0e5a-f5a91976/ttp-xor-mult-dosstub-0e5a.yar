rule TTP_XOR_MULT_DOSStub_0e5a {
  strings:
    $key_0e5a = { 5a 32 [2] 2e 2a [2] 69 28 [2] 2e 39 [2] 60 35 [2] 6c 3f [2] 7b 34 [2] 60 7a [2] 5d }

  condition:
    any of them
}